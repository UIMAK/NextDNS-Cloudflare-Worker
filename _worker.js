// ================================================================
// NextDNS Reverse Proxy - Cloudflare Worker (Modules 格式)
// ================================================================
// 环境变量配置（CF Dashboard -> Workers -> Settings -> Variables）：
//   NEXTDNS_ID   : 你的 NextDNS 配置 ID（必填），多个用逗号分隔
//   BASE_PATH    : 自定义路径前缀，不填默认 dns-query
//                  注意：不要设为 "/"，否则会匹配所有路径
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

// ── 上游请求头（固定不变，模块级复用）────────────────────────────────────────
const UPSTREAM_HEADERS = new Headers({
  'Content-Type': 'application/dns-message',
  'Accept':       'application/dns-message',
});

// ── CDN 真实客户端 IP 头配置 ──────────────────────────────────────────────────
// 按优先级从高到低排列，第一个匹配到有值的头即为真实客户端 IP
const CDN_IP_HEADERS = [
  'EO-Client-IP',        // 腾讯 EdgeOne
  'ali-real-client-ip',  // 阿里云 CDN
  'CF-Connecting-IP',    // Cloudflare
  'X-Forwarded-For',     // 通用（取第一个值）
  'X-Real-IP',           // 通用兜底
];

// ── 统一错误响应（携带 CORS 头，避免浏览器端 CORS 拦截错误信息）──────────────
const errResp = (body, status) =>
  new Response(body, { status, headers: { 'Access-Control-Allow-Origin': '*' } });

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

// ── 路径安全解码 ──────────────────────────────────────────────────────────────
// 循环解码直至稳定，彻底防止 %252e%252e 双重编码绕过；
// 捕获畸形编码（如 %E0%A4%A）的 URIError，降级返回空串
const safeDecodePath = (raw) => {
  if (!raw) return '';
  try {
    let prev, curr = raw;
    do {
      prev = curr;
      curr = decodeURIComponent(curr);
    } while (curr !== prev);
    return '/' + curr.replace(/^\/+/, '').replace(/\.\./g, '');
  } catch {
    return ''; // 畸形编码，忽略子路径
  }
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

// 增加出界检查，防止越界返回 NaN 污染后续计算
function readU16(buf, off) {
  if (off + 1 >= buf.length) throw new RangeError('readU16 out of bounds');
  return (buf[off] << 8) | buf[off + 1];
}

function writeU16BE(value) { return new Uint8Array([value >> 8, value & 0xff]); }

// 压缩指针分支增加 o+1 边界检查
function skipName(buf, off) {
  let o = off;
  while (o < buf.length) {
    const len = buf[o];
    if (len === 0) return o + 1;
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= buf.length) throw new RangeError('Compression pointer truncated');
      return o + 2;
    }
    o += 1 + len;
  }
  return o;
}

// 入口边界检查
function skipQuestion(buf, off) {
  if (off >= buf.length) throw new RangeError('Question truncated');
  return skipName(buf, off) + 4;
}

// 入口 + 出口双重边界检查
function skipRR(buf, off) {
  if (off >= buf.length) throw new RangeError('RR truncated');
  const endName = skipName(buf, off);
  if (endName + 10 > buf.length) throw new RangeError('RR header truncated');
  return endName + 10 + readU16(buf, endName + 8);
}

// 最小报文长度检查
function findSections(buf) {
  if (buf.length < 12) throw new RangeError('DNS message too short');
  const qd = readU16(buf, 4), an = readU16(buf, 6),
        ns = readU16(buf, 8), ar = readU16(buf, 10);
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipQuestion(buf, off);
  for (let i = 0; i < an; i++) off = skipRR(buf, off);
  for (let i = 0; i < ns; i++) off = skipRR(buf, off);
  return { ar, additionalStart: off };
}

// nameEnd、rdataEnd 双重越界检查
function parseAdditionalRecords(buf, arStart, arCount) {
  const recs = []; let off = arStart;
  for (let i = 0; i < arCount; i++) {
    if (off >= buf.length) break;
    const nameEnd = skipName(buf, off);
    if (nameEnd + 10 > buf.length) throw new RangeError('Additional RR header truncated');
    const type       = readU16(buf, nameEnd);
    const rdlen      = readU16(buf, nameEnd + 8);
    const rdataStart = nameEnd + 10;
    const rdataEnd   = rdataStart + rdlen;
    if (rdataEnd > buf.length) throw new RangeError('Additional RR rdata truncated');
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
  // optData = FAMILY(2) + SOURCE_PREFIX(1) + SCOPE_PREFIX(1) + ADDRESS(n)
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
    // 已存在 OPT record：移除旧的 ECS option（code=8），追加新的
    const rec = addRecs[optIdx];
    const options = [];
    let p = rec.rdataStart;
    while (p + 4 <= rec.rdataEnd) {
      const code = readU16(buf, p), len = readU16(buf, p + 2);
      const optEnd = p + 4 + len;
      if (optEnd > rec.rdataEnd) break;
      if (code !== 8) options.push(buf.slice(p, optEnd)); // 保留非 ECS option
      p = optEnd;
    }
    // options 可能为空数组，concatUint8 正确处理空输入
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
    new Uint8Array([0x00]),       // root name
    writeU16BE(41),               // TYPE = OPT
    writeU16BE(4096),             // CLASS = requestor's UDP payload size
    new Uint8Array([0, 0, 0, 0]), // TTL = extended RCODE + flags
    writeU16BE(ecsOpt.length),
    ecsOpt
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
  const left  = parts[0] ? parts[0].split(':').filter(Boolean) : [];
  const right = parts[1] ? parts[1].split(':').filter(Boolean) : [];
  const leftVals  = left.map(h => parseInt(h, 16));
  const rightVals = right.map(h => parseInt(h, 16));
  if (leftVals.some(isNaN) || rightVals.some(isNaN)) return null;
  // v4bytes 已占 2 个 word，missing 计算已预留，无需额外 pop()
  const missing = 8 - (leftVals.length + rightVals.length + (v4bytes ? 2 : 0));
  if (missing < 0) return null;
  const words = [...leftVals, ...Array(missing).fill(0), ...rightVals];
  if (v4bytes) {
    words.push((v4bytes[0] << 8) | v4bytes[1]);
    words.push((v4bytes[2] << 8) | v4bytes[3]);
  }
  if (words.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2]     = (words[i] >> 8) & 0xff;
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
  // >>> 0 强制转换为无符号 32 位整数，避免首字节 >= 128 时位运算产生负数
  const n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const inRange = (base, mask) => (n & mask) >>> 0 === (base >>> 0);
  return !(
    inRange(0x0a000000, 0xff000000) || // 10.0.0.0/8
    inRange(0xac100000, 0xfff00000) || // 172.16.0.0/12
    inRange(0xc0a80000, 0xffff0000) || // 192.168.0.0/16
    inRange(0x7f000000, 0xff000000) || // 127.0.0.0/8
    inRange(0xa9fe0000, 0xffff0000) || // 169.254.0.0/16
    inRange(0x64400000, 0xffc00000) || // 100.64.0.0/10 (CGNAT)
    inRange(0x00000000, 0xff000000) || // 0.0.0.0/8
    (b[0] & 0xf0) === 0xe0 ||          // 224.0.0.0/4 (组播)
    (b[0] & 0xf0) === 0xf0             // 240.0.0.0/4 (保留)
  );
}

function isPublicIPv6(ip) {
  const b = parseIPv6(ip);
  if (!b) return false;
  const b0 = b[0], b1 = b[1];

  // [fix] 补充 IPv4-mapped (::ffff:0:0/96) 和 NAT64 (64:ff9b::/96) 地址段
  // 这两类地址的真实公网性取决于其内嵌的 IPv4 地址，需提取后单独判断
  const isV4Mapped =
    b.slice(0, 10).every(x => x === 0) && b[10] === 0xff && b[11] === 0xff;
  const isNAT64 =
    b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b &&
    b.slice(4, 12).every(x => x === 0);

  if (isV4Mapped || isNAT64) {
    // 提取内嵌的 IPv4 地址（最后 4 字节），委托给 isPublicIPv4 判断
    const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
    return isPublicIPv4(v4);
  }

  return !(
    b.every(x => x === 0) ||                               // ::（未指定）
    (b.slice(0, 15).every(x => x === 0) && b[15] === 1) || // ::1（回环）
    (b0 & 0xfe) === 0xfc ||                                // fc00::/7（ULA）
    (b0 === 0xfe && (b1 & 0xc0) === 0x80) ||               // fe80::/10（链路本地）
    b0 === 0xff                                            // ff00::/8（组播）
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
    return errResp('Method Not Allowed', 405);
  }

  const NEXTDNS_IDS        = (env.NEXTDNS_ID ?? '').split(',').map(s => s.trim()).filter(Boolean);
  const BASE_PATH          = env.BASE_PATH ?? '';
  const PRIMARY_TIMEOUT_MS = (() => {
    const n = parseInt(env.TIMEOUT_MS, 10);
    return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
  })();

  // [fix] 过滤掉纯斜杠配置（BASE_PATH='/' 会匹配所有路径，是常见配置失误）
  const normalizedBase = BASE_PATH.replace(/^\/+|\/+$/g, ''); // 去除首尾斜杠
  const basePath = normalizedBase ? `/${normalizedBase}` : '/dns-query';

  if (
    clientUrl.pathname !== basePath &&
    !clientUrl.pathname.startsWith(basePath + '/')
  ) {
    return errResp('Not Found', 404);
  }

  if (NEXTDNS_IDS.length === 0) {
    return errResp('Server misconfiguration: NEXTDNS_ID not set', 500);
  }

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
    if (!dnsParam) return errResp('Missing dns parameter', 400);
    try {
      dnsWire = base64urlDecode(dnsParam);
    } catch {
      return errResp('Invalid dns parameter', 400);
    }
  } else {
    // POST 请求必须携带正确的 Content-Type
    const ct = request.headers.get('Content-Type') || '';
    if (!ct.startsWith('application/dns-message')) {
      return errResp('Unsupported Media Type', 415);
    }
    const cl = request.headers.get('Content-Length');
    if (cl && parseInt(cl, 10) > MAX_BODY) {
      return errResp('Payload Too Large', 413);
    }
    try {
      const buf = await request.arrayBuffer();
      if (buf.byteLength > MAX_BODY) return errResp('Payload Too Large', 413);
      dnsWire = new Uint8Array(buf);
    } catch {
      return errResp('Failed to read request body', 400);
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

  const devicePath = safeDecodePath(clientUrl.pathname.substring(basePath.length));

  const tryFetch = async (upstreamUrl, signal) => {
    const req = new Request(upstreamUrl, {
      method:   'POST',
      headers:  UPSTREAM_HEADERS,
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
      return errResp('Bad Gateway', 502);
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