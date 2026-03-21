// ================================================================
// NextDNS Reverse Proxy - Cloudflare Worker (Modules 格式)
// ================================================================
// 环境变量配置（CF Dashboard -> Workers -> Settings -> Variables）：
//   NEXTDNS_ID   : 你的 NextDNS 配置 ID（必填），多个用逗号分隔
//   BASE_PATH    : 自定义路径，不填默认 dns-query
//   FALLBACK_URL : 备用 DoH，不填默认 https://dns.google/dns-query
//   TIMEOUT_MS   : 主上游超时时间（毫秒），不填默认 2500
// ================================================================

const NEXTDNS_BASE        = 'https://dns.nextdns.io';
const DEFAULT_FALLBACK    = 'https://dns.google/dns-query';
const MAX_BODY            = 64 * 1024; // 64KB，符合 DNS 消息最大长度标准
const DEFAULT_TIMEOUT_MS  = 2500;      // 主上游默认超时时间（毫秒）
const FALLBACK_TIMEOUT_MS = 1500;      // 备用上游超时时间（毫秒）
const ECS_V4_PREFIX       = 24;        // IPv4 ECS 前缀长度
const ECS_V6_PREFIX       = 48;        // IPv6 ECS 前缀长度

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Access-Control-Max-Age':       '86400',
};

// ── CDN 真实客户端 IP 头配置 ──────────────────────────────────────────────────
// 按优先级从高到低排列，第一个匹配到有值的头即为真实客户端 IP
const CDN_IP_HEADERS = [
  'EO-Client-IP',        // 腾讯 EdgeOne
  'ali-real-client-ip',  // 阿里云 CDN
  'CF-Connecting-IP',    // Cloudflare
  'X-Forwarded-For',     // 通用（取第一个值）
  'X-Real-IP',           // 通用兜底
];

// ── withTimeout ───────────────────────────────────────────────────────────────
const withTimeout = async (fetchFn, ms) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetchFn(controller.signal);
  } catch (err) {
    if (err.name === 'AbortError') {
      const e = new Error('Timeout');
      e.name = 'TimeoutError';
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
};

// ── CDN IP 提取 ───────────────────────────────────────────────────────────────
const getClientIP = (headers) => {
  for (const name of CDN_IP_HEADERS) {
    const val = headers.get(name);
    if (!val) continue;
    const ip = val.split(',')[0].trim();
    if (ip) return ip;
  }
  return null;
};

// ═════════════════════════════════════════════════════════════════════════════
// DNS 报文层 ECS 注入
// ═════════════════════════════════════════════════════════════════════════════

function base64urlDecode(s) {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function readU16(buf, off) { return (buf[off] << 8) | buf[off + 1]; }
function writeU16BE(value) { return new Uint8Array([value >> 8, value & 0xff]); }

function skipName(buf, off) {
  let o = off;
  while (o < buf.length) {
    const len = buf[o];
    if (len === 0) return o + 1;
    if ((len & 0xc0) === 0xc0) return o + 2;
    o += 1 + len;
  }
  return o;
}
function skipQuestion(buf, off) { return skipName(buf, off) + 4; }
function skipRR(buf, off) {
  const endName = skipName(buf, off);
  return endName + 10 + readU16(buf, endName + 8);
}

function findSections(buf) {
  const qd = readU16(buf, 4), an = readU16(buf, 6),
        ns = readU16(buf, 8), ar = readU16(buf, 10);
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipQuestion(buf, off);
  for (let i = 0; i < an; i++) off = skipRR(buf, off);
  for (let i = 0; i < ns; i++) off = skipRR(buf, off);
  return { ar, additionalStart: off };
}

function parseAdditionalRecords(buf, arStart, arCount) {
  const recs = []; let off = arStart;
  for (let i = 0; i < arCount; i++) {
    const nameEnd = skipName(buf, off);
    const type = readU16(buf, nameEnd);
    const rdlen = readU16(buf, nameEnd + 8);
    const rdataStart = nameEnd + 10;
    const rdataEnd = rdataStart + rdlen;
    recs.push({ nameEnd, type, rdataStart, rdataEnd });
    off = rdataEnd;
  }
  return recs;
}

function concatUint8(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len); let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function buildEcsOption(ipBytes, family, prefixLen) {
  const count = Math.ceil(prefixLen / 8);
  const trimmed = new Uint8Array(count);
  for (let i = 0; i < count; i++) trimmed[i] = ipBytes[i] || 0;
  const rem = prefixLen % 8;
  if (rem && count > 0) trimmed[count - 1] &= (0xff << (8 - rem));
  const optData = concatUint8(writeU16BE(family),
    new Uint8Array([prefixLen & 0xff, 0]), trimmed);
  return concatUint8(writeU16BE(8), writeU16BE(optData.length), optData);
}

function injectECS(buf, clientIp) {
  const ip = parseIp(clientIp);
  if (!ip) return buf;
  const prefixLen = ip.family === 1 ? ECS_V4_PREFIX : ECS_V6_PREFIX;
  const ecsOpt = buildEcsOption(ip.bytes, ip.family, prefixLen);
  const { ar, additionalStart } = findSections(buf);
  const addRecs = parseAdditionalRecords(buf, additionalStart, ar);
  const optIdx = addRecs.findIndex(r => r.type === 41);

  if (optIdx !== -1) {
    const rec = addRecs[optIdx];
    const options = [];
    let p = rec.rdataStart;
    while (p + 4 <= rec.rdataEnd) {
      const code = readU16(buf, p), len = readU16(buf, p + 2);
      const optEnd = p + 4 + len;
      if (optEnd > rec.rdataEnd) break;
      if (code !== 8) options.push(buf.slice(p, optEnd));
      p = optEnd;
    }
    const newRdata = concatUint8(...options, ecsOpt);
    return concatUint8(
      buf.slice(0, rec.nameEnd + 8),
      writeU16BE(newRdata.length),
      newRdata,
      buf.slice(rec.rdataEnd)
    );
  }

  // 没有 OPT record，新建一个并追加
  const arCount = readU16(buf, 10);
  const optRecord = concatUint8(
    new Uint8Array([0x00]), writeU16BE(41), writeU16BE(4096),
    new Uint8Array([0, 0, 0, 0]), writeU16BE(ecsOpt.length), ecsOpt
  );
  const newBuf = concatUint8(buf, optRecord);
  const ar2 = arCount + 1;
  newBuf[10] = (ar2 >> 8) & 0xff;
  newBuf[11] = ar2 & 0xff;
  return newBuf;
}

// ── IP 解析与公网判断 ──────────────────────────────────────────────────────────

function parseIPv4(str) {
  const parts = str.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n < 0 || n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseIPv6(str) {
  let main = str, v4bytes = null;
  const lastColon = str.lastIndexOf(':'), lastDot = str.lastIndexOf('.');
  if (lastDot > lastColon) {
    v4bytes = parseIPv4(str.slice(lastColon + 1));
    if (!v4bytes) return null;
    main = str.slice(0, lastColon);
  }
  const parts = main.split('::');
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
  const leftVals = left.map(h => parseInt(h, 16));
  const rightVals = right.map(h => parseInt(h, 16));
  if (leftVals.some(isNaN) || rightVals.some(isNaN)) return null;
  const missing = 8 - (leftVals.length + rightVals.length + (v4bytes ? 2 : 0));
  if (missing < 0) return null;
  const words = [...leftVals, ...Array(missing).fill(0), ...rightVals];
  if (v4bytes) {
    words.pop();
    words.push((v4bytes[0] << 8) | v4bytes[1]);
    words.push((v4bytes[2] << 8) | v4bytes[3]);
  }
  if (words.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (words[i] >> 8) & 0xff;
    out[i * 2 + 1] = words[i] & 0xff;
  }
  return out;
}

function parseIp(str) {
  if (!str) return null;
  if (str.includes(':')) {
    const bytes = parseIPv6(str);
    return bytes ? { family: 2, bytes } : null;
  }
  const bytes = parseIPv4(str);
  return bytes ? { family: 1, bytes } : null;
}

function isPublicIPv4(ip) {
  const b = parseIPv4(ip);
  if (!b) return false;
  const n = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  const inRange = (base, mask) => (n & mask) === base;
  return !(
    inRange(0x0a000000, 0xff000000) || inRange(0xac100000, 0xfff00000) ||
    inRange(0xc0a80000, 0xffff0000) || inRange(0x7f000000, 0xff000000) ||
    inRange(0xa9fe0000, 0xffff0000) || inRange(0x64400000, 0xffc00000) ||
    inRange(0x00000000, 0xff000000) ||
    (b[0] & 0xf0) === 0xe0 || (b[0] & 0xf0) === 0xf0
  );
}

function isPublicIPv6(ip) {
  const b = parseIPv6(ip);
  if (!b) return false;
  const b0 = b[0], b1 = b[1];
  return !(
    b.every(x => x === 0) ||
    (b.slice(0, 15).every(x => x === 0) && b[15] === 1) ||
    (b0 & 0xfe) === 0xfc ||
    (b0 === 0xfe && (b1 & 0xc0) === 0x80) ||
    b0 === 0xff
  );
}

function isPublicIp(ip) {
  if (!ip) return false;
  return ip.includes(':') ? isPublicIPv6(ip) : isPublicIPv4(ip);
}

// ═════════════════════════════════════════════════════════════════════════════
// 主处理逻辑
// ═════════════════════════════════════════════════════════════════════════════

async function handleRequest(request, env) {
  const clientUrl = new URL(request.url);

  // 处理 CORS 预检请求
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // DoH 只允许 GET 和 POST
  if (!['GET', 'POST'].includes(request.method)) {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const NEXTDNS_IDS        = (env.NEXTDNS_ID ?? '').split(',').map(s => s.trim()).filter(Boolean);
  const BASE_PATH          = env.BASE_PATH ?? '';
  const PRIMARY_TIMEOUT_MS = (() => {
    const n = parseInt(env.TIMEOUT_MS, 10);
    return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
  })();

  const basePath = BASE_PATH
    ? '/' + BASE_PATH.replace(/^\//, '')
    : '/dns-query';

  if (
    clientUrl.pathname !== basePath &&
    !clientUrl.pathname.startsWith(basePath + '/')
  ) {
    return new Response('Not Found', { status: 404 });
  }

  if (NEXTDNS_IDS.length === 0) {
    return new Response('Server misconfiguration: NEXTDNS_ID not set', { status: 500 });
  }

  // FALLBACK_URL 格式校验
  let fallbackBase;
  try {
    fallbackBase = new URL(env.FALLBACK_URL || DEFAULT_FALLBACK).toString();
  } catch {
    fallbackBase = DEFAULT_FALLBACK;
  }

  // 获取真实客户端 IP
  const clientIP = getClientIP(request.headers);

  // 读取 DNS 报文
  let dnsWire;
  if (request.method === 'GET') {
    const dnsParam = clientUrl.searchParams.get('dns');
    if (!dnsParam) return new Response('Missing dns parameter', { status: 400 });
    try {
      dnsWire = base64urlDecode(dnsParam);
    } catch {
      return new Response('Invalid dns parameter', { status: 400 });
    }
  } else {
    // POST 请求必须携带正确的 Content-Type
    const ct = request.headers.get('Content-Type') || '';
    if (!ct.startsWith('application/dns-message')) {
      return new Response('Unsupported Media Type', { status: 415 });
    }
    const cl = request.headers.get('Content-Length');
    if (cl && parseInt(cl, 10) > MAX_BODY) {
      return new Response('Payload Too Large', { status: 413 });
    }
    try {
      const buf = await request.arrayBuffer();
      if (buf.byteLength > MAX_BODY) return new Response('Payload Too Large', { status: 413 });
      dnsWire = new Uint8Array(buf);
    } catch {
      return new Response('Failed to read request body', { status: 400 });
    }
  }

  // 注入 ECS，遇到畸形报文时静默降级为透传原始报文
  let mutatedWire = dnsWire;
  if (isPublicIp(clientIP)) {
    try {
      mutatedWire = injectECS(dnsWire, clientIP);
    } catch {
      mutatedWire = dnsWire;
    }
  }

  // 构建转发给上游的请求头（统一用 POST 转发）
  // ECS 已在 DNS 报文层注入子网，无需再传 X-Forwarded-For 暴露完整 IP
  const upstreamHeaders = new Headers();
  upstreamHeaders.set('Content-Type', 'application/dns-message');
  upstreamHeaders.set('Accept', 'application/dns-message');

  const devicePath = clientUrl.pathname.substring(basePath.length);

  const tryFetch = async (upstreamUrl, signal) => {
    const req = new Request(upstreamUrl, {
      method:   'POST',
      headers:  upstreamHeaders,
      body:     mutatedWire,
      redirect: 'follow',
      signal,
    });
    const response = await fetch(req);
    if (response.status >= 500) {
      const err = new Error(`Upstream error: ${response.status}`);
      err.name = 'UpstreamError';
      throw err;
    }
    const respHeaders = new Headers(response.headers);
    respHeaders.set('X-Proxied-By', 'CF-Worker-NextDNS');
    respHeaders.set('Access-Control-Allow-Origin', '*');
    return new Response(response.body, {
      status:     response.status,
      statusText: response.statusText,
      headers:    respHeaders,
    });
  };

  // 随机选一个 NextDNS ID
  const selectedId = NEXTDNS_IDS[Math.floor(Math.random() * NEXTDNS_IDS.length)];
  const primaryUrl = new URL(`${NEXTDNS_BASE}/${selectedId}${devicePath}`).toString();

  try {
    return await withTimeout(
      (signal) => tryFetch(primaryUrl, signal),
      PRIMARY_TIMEOUT_MS
    );
  } catch (primaryErr) {
    try {
      const resp        = await withTimeout(
        (signal) => tryFetch(fallbackBase, signal),
        FALLBACK_TIMEOUT_MS
      );
      const respHeaders = new Headers(resp.headers);
      respHeaders.set('X-Fallback', primaryErr.name === 'TimeoutError' ? 'primary-timeout' : 'primary-error');
      respHeaders.set('Access-Control-Allow-Origin', '*');
      return new Response(resp.body, {
        status:     resp.status,
        statusText: resp.statusText,
        headers:    respHeaders,
      });
    } catch {
      return new Response('Bad Gateway', { status: 502 });
    }
  }
}

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  }
};

export async function onRequest(context) {
  return handleRequest(context.request, context.env);
}
