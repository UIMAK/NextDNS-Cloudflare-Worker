// NextDNS DoH Proxy
// 自动检测运行平台：Cloudflare Workers/Pages、Vercel Edge、Netlify Edge
// ================================================================
// 环境变量配置：
//   NEXTDNS_ID   : NextDNS 配置 ID（必填），多个用逗号分隔
//   FALLBACK_URL : 备用 DoH 服务器（默认 https://dns.google/dns-query）
//   TIMEOUT_MS   : 主上游超时时间（毫秒，默认 2500，最大 30000）
//   BASE_PATH    : 路径前缀（Cloudflare 用，默认 /dns-query）
//   MOUNT_PATH   : 挂载路径（Vercel/Netlify 用，默认 /uimak）
// ================================================================

const NEXTDNS_BASE        = 'https://dns.nextdns.io';
const DEFAULT_FALLBACK    = 'https://dns.google/dns-query';
const MAX_BODY            = 64 * 1024;
const MAX_RESPONSE        = 64 * 1024;
const DEFAULT_TIMEOUT_MS  = 2500;
const FALLBACK_TIMEOUT_MS = 1500;
const MAX_TIMEOUT_MS      = 30000;
// 注意：这里存储的是前缀长度（单位：bit），而非前缀本身
const ECS_V4_PREFIX_LEN   = 24;
const ECS_V6_PREFIX_LEN   = 48;

const CORS_HEADERS = Object.freeze({
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept',
  'Access-Control-Max-Age':       '86400',
});

const UPSTREAM_HEADERS = Object.freeze({
  'Content-Type': 'application/dns-message',
  'Accept':       'application/dns-message',
});

// 模块级常量：避免每次请求创建临时数组
const ALLOWED_METHODS = new Set(['GET', 'POST']);

// 模块级正则常量：避免 base64urlDecode 每次调用时重新解析正则字面量
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

// DNS 协议相关常量提取，消除魔法数字
const DNS_CONSTANTS = Object.freeze({
  HEADER_SIZE:           12,
  OFFSET_QD:              4,
  OFFSET_AN:              6,
  OFFSET_NS:              8,
  OFFSET_AR:             10,
  TYPE_OPT:              41,
  ECS_OPTION_CODE:        8,
  EDNS_UDP_PAYLOAD_SIZE:  4096,
});

// safeDecodePath 解码迭代上限
const MAX_DECODE_PASSES = 5;

// ================================================================
// 平台检测（模块加载时一次性执行，结果缓存为常量 PLATFORM）
// ================================================================

const detectPlatform = () => {
  if (typeof Deno !== 'undefined' && typeof Deno.env?.get === 'function') return 'netlify';
  if (typeof process !== 'undefined' && process.env) return 'vercel';
  return 'cloudflare';
};

const PLATFORM = detectPlatform();

const getEnv = (key, env) => {
  if (PLATFORM === 'netlify') return Deno.env.get(key);
  if (PLATFORM === 'vercel')  return process.env[key];
  return env?.[key];
};

const CLIENT_IP_HEADERS = Object.freeze({
  cloudflare: ['EO-Client-IP', 'ali-real-client-ip', 'X-Forwarded-For', 'CF-Connecting-IP',          ],
  vercel:     ['EO-Client-IP', 'ali-real-client-ip', 'X-Forwarded-For', 'X-Vercel-Forwarded-For',    ],
  netlify:    ['EO-Client-IP', 'ali-real-client-ip', 'X-Forwarded-For', 'X-Nf-Client-Connection-Ip', ],
});

const errResp = (body, status) => new Response(body, {
  status,
  headers: { ...CORS_HEADERS, 'Content-Type': 'text/plain;charset=UTF-8' },
});

const capitalize = str => str.charAt(0).toUpperCase() + str.slice(1);

// 自定义错误工厂，提升代码可维护性
const createCustomError = (name, message, cause) => {
  const err = new Error(message);
  err.name = name;
  if (cause) err.cause = cause;
  return err;
};

// ================================================================
// 工具函数
// ================================================================

const withTimeout = async (fetchFn, ms) => {
  if (ms <= 0) throw new Error('Timeout must be positive');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetchFn(controller.signal);
  } catch (err) {
    if (err.name === 'AbortError') {
      throw createCustomError('TimeoutError', 'Timeout', err);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
};

// stripIPv6Brackets：统一剥离 IPv6 字面量的方括号
// 使用 /^\[(.*)\]$/ 确保只处理成对括号，畸形输入（如 [::1 或 ::1]）原样返回，
// 后续 parseIp 会返回 null，ECS 不注入，安全降级。
// 将正则提取为具名函数，消除 getClientIP 内两处处理相同问题
const IPV6_BRACKET_RE = /^\[(.*)\]$/;
const stripIPv6Brackets = ip => ip.replace(IPV6_BRACKET_RE, '$1');

const getClientIP = (headers, context) => {
  if (PLATFORM === 'netlify' && context?.ip) {
    const ip = context.ip.trim();
    // Netlify context.ip 对 IPv6 可能带方括号（如 [::1]）
    const stripped = stripIPv6Brackets(ip);
    if (stripped) return stripped;
  }
  const headersToCheck = CLIENT_IP_HEADERS[PLATFORM] ?? CLIENT_IP_HEADERS.cloudflare;
  for (const name of headersToCheck) {
    const val = headers.get(name);
    if (!val) continue;
    // HTTP 头部 X-Forwarded-For 等字段取第一个 IP，再统一剥括号
    const ip = stripIPv6Brackets(val.split(',')[0].trim());
    if (ip) return ip;
  }
  return null;
};

const isValidSegment = seg => seg !== '' && !seg.startsWith('.') && seg !== '..';

const safeDecodePath = (raw) => {
  if (!raw || raw === '/') return '';
  try {
    let prev, curr = raw;
    for (let i = 0; i < MAX_DECODE_PASSES; i++) {
      prev = curr;
      curr = decodeURIComponent(curr);
      if (curr === prev) break;
    }
    const cleaned = curr.replace(/^\/+/, '').split('/').filter(isValidSegment).join('/');
    return cleaned ? '/' + cleaned : '';
  } catch {
    return '';
  }
};

const encodeDevicePath = (devicePath) => {
  if (!devicePath) return '';
  const segments = devicePath.split('/').filter(isValidSegment).map(encodeURIComponent);
  return segments.length > 0 ? '/' + segments.join('/') : '';
};

function base64urlDecode(s) {
  if (typeof s !== 'string') throw new TypeError('Input must be a string');
  if (s.length === 0) throw new Error('Invalid base64url: empty string');
  if (s.length % 4 === 1) throw new Error('Invalid base64url length');
  if (!BASE64URL_RE.test(s)) throw new Error('Invalid base64url characters');
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  try {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  } catch {
    throw new Error('Invalid base64 encoding');
  }
}

// ================================================================
// DNS 消息处理
// ================================================================

function readU16(buf, off) {
  if (off < 0 || off + 2 > buf.length) throw new RangeError('readU16 out of bounds');
  return (buf[off] << 8) | buf[off + 1];
}

function writeU16BE(value) {
  if (value < 0 || value > 0xFFFF) throw new RangeError('Value out of 16-bit range');
  return new Uint8Array([value >> 8, value & 0xff]);
}

function skipName(buf, off) {
  let o = off, steps = 0;
  while (o < buf.length) {
    if (++steps > 255) throw new RangeError('DNS name too long or pointer loop');
    const len = buf[o];
    if (len === 0) return o + 1;
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= buf.length) throw new RangeError('Compression pointer truncated');
      return o + 2;
    }
    o += 1 + len;
  }
  // 到达缓冲区末尾仍未找到结束符（0x00 或压缩指针），说明消息被截断
  throw new RangeError('DNS name label truncated at buffer end');
}

function skipQuestion(buf, off) {
  if (off >= buf.length) throw new RangeError('Question truncated');
  const endName = skipName(buf, off);
  if (endName + 4 > buf.length) throw new RangeError('Question QTYPE/QCLASS truncated');
  return endName + 4;
}

function skipRR(buf, off) {
  if (off >= buf.length) throw new RangeError('RR truncated');
  const endName = skipName(buf, off);
  if (endName + 10 > buf.length) throw new RangeError('RR header truncated');
  const rdlen = readU16(buf, endName + 8);
  const rrEnd = endName + 10 + rdlen;
  if (rrEnd > buf.length) throw new RangeError('RR rdata truncated');
  return rrEnd;
}

function findSections(buf) {
  if (buf.length < DNS_CONSTANTS.HEADER_SIZE) throw new RangeError('DNS message too short');
  
  const qdCount = readU16(buf, DNS_CONSTANTS.OFFSET_QD);
  const anCount = readU16(buf, DNS_CONSTANTS.OFFSET_AN);
  const nsCount = readU16(buf, DNS_CONSTANTS.OFFSET_NS);
  const arCount = readU16(buf, DNS_CONSTANTS.OFFSET_AR);
  
  let off = DNS_CONSTANTS.HEADER_SIZE;
  for (let i = 0; i < qdCount; i++) off = skipQuestion(buf, off);
  for (let i = 0; i < anCount; i++) off = skipRR(buf, off);
  for (let i = 0; i < nsCount; i++) off = skipRR(buf, off);
  
  return { arCount, additionalStart: off };
}

function parseAdditionalRecords(buf, arStart, arCount) {
  const recs = [];
  let off = arStart;
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
  if (arrays.length === 0) return new Uint8Array(0);
  let len = 0;
  for (const a of arrays) {
    if (!(a instanceof Uint8Array)) throw new TypeError('All arguments must be Uint8Array');
    len += a.length;
  }
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function buildEcsOption(ipBytes, family, prefixLen) {
  const count   = Math.ceil(prefixLen / 8);
  const trimmed = new Uint8Array(count);
  for (let i = 0; i < Math.min(count, ipBytes.length); i++) {
    trimmed[i] = ipBytes[i];
  }
  const rem = prefixLen % 8;
  if (rem && count > 0) trimmed[count - 1] &= (0xff << (8 - rem));
  const optData = concatUint8(writeU16BE(family), new Uint8Array([prefixLen & 0xff, 0]), trimmed);
  return concatUint8(writeU16BE(DNS_CONSTANTS.ECS_OPTION_CODE), writeU16BE(optData.length), optData);
}

function injectECS(buf, parsedIp) {
  if (!parsedIp) return buf;
  const prefixLen = parsedIp.family === 1 ? ECS_V4_PREFIX_LEN : ECS_V6_PREFIX_LEN;
  let ecsOpt;
  try {
    ecsOpt = buildEcsOption(parsedIp.bytes, parsedIp.family, prefixLen);
  } catch (e) {
    console.warn('Could not build ECS option:', e.message);
    return buf;
  }

  const { arCount, additionalStart } = findSections(buf);
  const addRecs = parseAdditionalRecords(buf, additionalStart, arCount);
  const optIdx  = addRecs.findIndex(r => r.type === DNS_CONSTANTS.TYPE_OPT);

  if (optIdx !== -1) {
    const rec = addRecs[optIdx];
    // 检查 OPT record 中是否已存在 ECS option
    let p = rec.rdataStart;
    while (p + 4 <= rec.rdataEnd) {
      const code   = readU16(buf, p);
      const len    = readU16(buf, p + 2);
      const optEnd = p + 4 + len;
      if (optEnd > rec.rdataEnd) break;
      if (code === DNS_CONSTANTS.ECS_OPTION_CODE) {
        // 已有 ECS — 保留上游注入的 ECS，不覆写
        return buf;
      }
      p = optEnd;
    }
    // 无 ECS — 在已有 OPT rdata 后追加 ECS option
    const existingRdata = buf.slice(rec.rdataStart, rec.rdataEnd);
    const newRdata = concatUint8(existingRdata, ecsOpt);
    return concatUint8(
      buf.slice(0, rec.nameEnd + 8),
      writeU16BE(newRdata.length),
      newRdata,
      buf.slice(rec.rdataEnd)
    );
  }

  const optRecord = concatUint8(
    new Uint8Array([0x00]),
    writeU16BE(DNS_CONSTANTS.TYPE_OPT),
    writeU16BE(DNS_CONSTANTS.EDNS_UDP_PAYLOAD_SIZE),
    new Uint8Array([0, 0, 0, 0]),
    writeU16BE(ecsOpt.length),
    ecsOpt
  );
  const newBuf = concatUint8(buf, optRecord);
  const newArCount = arCount + 1;
  newBuf[DNS_CONSTANTS.OFFSET_AR]     = (newArCount >> 8) & 0xff;
  newBuf[DNS_CONSTANTS.OFFSET_AR + 1] = newArCount & 0xff;
  return newBuf;
}

// ================================================================
// IP 解析和验证
// ================================================================

function parseIPv4(str) {
  if (typeof str !== 'string') return null;
  const parts = str.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d+$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n < 0 || n > 255 || !Number.isFinite(n)) return null;
    out[i] = n;
  }
  return out;
}

const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

function parseIPv6(str) {
  if (typeof str !== 'string') return null;
  let main = str, v4bytes = null;
  if (str.includes('.')) {
    // 字符串含 '.' 说明可能有嵌入 IPv4（如 ::ffff:1.2.3.4 或 64:ff9b::1.2.3.4）
    // 用 lastIndexOf(':') 找到 IPv4 部分的起始冒号
    const lastColon = str.lastIndexOf(':');
    v4bytes = parseIPv4(str.slice(lastColon + 1));
    if (!v4bytes) return null;
    // 修复：当 lastColon 前一个字符也是 ':' 时（即 '::' 结构），
    // main 必须包含第二个冒号才能保留 '::' 标记，否则 split('::') 无法识别省略
    // 例：'64:ff9b::1.2.3.4' lastColon=8，str[7]=':' => main='64:ff9b::'（含第二个冒号）
    if (lastColon > 0 && str[lastColon - 1] === ':') {
      main = str.slice(0, lastColon + 1);
    } else {
      main = str.slice(0, lastColon);
    }
  }
  const parts = main.split('::');
  if (parts.length > 2) return null;
  const hasElision = parts.length === 2;
  const left  = parts[0] ? parts[0].split(':').filter(s => s.length > 0) : [];
  const right = parts[1] ? parts[1].split(':').filter(s => s.length > 0) : [];
  if (left.some(h => !HEX_GROUP.test(h)) || right.some(h => !HEX_GROUP.test(h))) return null;
  const leftVals  = left.map(h => parseInt(h, 16));
  const rightVals = right.map(h => parseInt(h, 16));
  if (leftVals.some(Number.isNaN) || rightVals.some(Number.isNaN)) return null;
  const groupCount = leftVals.length + rightVals.length + (v4bytes ? 2 : 0);
  const missing    = 8 - groupCount;
  if (!hasElision && missing !== 0) return null;
  if (missing < 0) return null;
  // hasElision=true 时 :: 必须至少代表一个零组（missing >= 1）；
  // 若 groupCount > 0 且 missing === 0，说明 :: 什么都没省略，格式非法（RFC 5952）
  if (hasElision && missing === 0 && groupCount > 0) return null;
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
  if (!str || typeof str !== 'string') return null;
  if (str.includes(':')) {
    const bytes = parseIPv6(str);
    return bytes ? { family: 2, bytes } : null;
  }
  const bytes = parseIPv4(str);
  return bytes ? { family: 1, bytes } : null;
}

function allZero(buf, start, end) {
  for (let i = start; i < end; i++) {
    if (i >= buf.length || buf[i] !== 0) return false;
  }
  return true;
}

function isPublicIPv4Bytes(b) {
  const n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  const inRange = (base, mask) => (n & mask) >>> 0 === (base & mask) >>> 0;
  return !(
    inRange(0x0a000000, 0xff000000) || inRange(0xac100000, 0xfff00000) ||
    inRange(0xc0a80000, 0xffff0000) || inRange(0x7f000000, 0xff000000) ||
    inRange(0xa9fe0000, 0xffff0000) || inRange(0x64400000, 0xffc00000) ||
    inRange(0x00000000, 0xff000000) || (b[0] & 0xf0) === 0xe0 || (b[0] & 0xf0) === 0xf0
  );
}

// 非公网 IPv6 前缀匹配器表。
// 每个条目是一个 (b: Uint8Array) => boolean 谓词，b 为完整 16 字节地址。
const NON_PUBLIC_IPV6_CHECKS = Object.freeze([
  b => allZero(b, 0, 16),                                                         // :: (unspecified)
  b => allZero(b, 0, 15) && b[15] === 1,                                         // ::1 (loopback)
  b => (b[0] & 0xfe) === 0xfc,                                                    // fc00::/7 (ULA, RFC 4193)
  b => b[0] === 0xfe && (b[1] & 0xc0) === 0x80,                                  // fe80::/10 (link-local, RFC 4291)
  b => b[0] === 0xff,                                                              // ff00::/8 (multicast)
  b => b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8,         // 2001:db8::/32 (documentation, RFC 3849)
  b => b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x10, // 2001:10::/28 (deprecated)
  b => b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x20, // 2001:20::/28 (deprecated)
]);

function isPublicIPv6Bytes(b) {
  const [b0, b1, b2, b3] = b;
  const isV4Mapped = allZero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff;
  // isNAT64：Well-Known 前缀 64:ff9b::/96（RFC 6052），IPv4 嵌入在 bytes[12..15]
  const isNAT64 = b0 === 0x00 && b1 === 0x64 && b2 === 0xff && b3 === 0x9b && allZero(b, 4, 12);
  // isLocalNAT64：RFC 8215 本地 NAT64 前缀 64:ff9b:1::/48
  // 按 RFC 6052 Section 2.2 /48 格式：IPv4 分布在 bytes[6..7]（高16位）和 bytes[9..10]（低16位），
  // byte[8] 为保留零位（u bits）。isNAT64 的 allZero(b,4,12) 已排除 b[4..5]=[0x00,0x01] 的情况，
  // 因此两者互斥，无需额外交集过滤。
  const isLocalNAT64 = b0 === 0x00 && b1 === 0x64 && b2 === 0xff && b3 === 0x9b
    && b[4] === 0x00 && b[5] === 0x01;
  const is6to4 = b0 === 0x20 && b1 === 0x02;
  if (isV4Mapped || isNAT64 || is6to4) {
    // 6to4 的 IPv4 嵌入在 bytes[2..5]；v4-mapped 和 Well-Known NAT64(/96) 在 bytes[12..15]
    const v4Bytes = is6to4 ? b.slice(2, 6) : b.slice(12, 16);
    return isPublicIPv4Bytes(v4Bytes);
  }
  if (isLocalNAT64) {
    // RFC 6052 /48 前缀格式：IPv4 bytes[0..1] 在 addr[6..7]，bytes[2..3] 在 addr[9..10]
    const v4Bytes = new Uint8Array([b[6], b[7], b[9], b[10]]);
    return isPublicIPv4Bytes(v4Bytes);
  }
  return !NON_PUBLIC_IPV6_CHECKS.some(fn => fn(b));
}

function isPublicParsedIp(parsed) {
  if (!parsed) return false;
  return parsed.family === 1
    ? isPublicIPv4Bytes(parsed.bytes)
    : isPublicIPv6Bytes(parsed.bytes);
}

// ================================================================
// 请求解析辅助函数
// ================================================================

function parseConfig(env) {
  const idsStr = getEnv('NEXTDNS_ID', env) || '';
  if (!idsStr.trim()) return { error: 'Server misconfiguration: NEXTDNS_ID not set' };
  const ids = idsStr
    .split(',')
    .map(s => s.replace(/[^a-zA-Z0-9_-]/g, ''))
    .filter(Boolean);
  if (ids.length === 0) return { error: 'Server misconfiguration: No valid NEXTDNS_ID found' };
  
  const rawTimeout = getEnv('TIMEOUT_MS', env);
  const parsed     = rawTimeout ? parseInt(rawTimeout, 10) : NaN;
  const primaryTimeoutMs = Number.isFinite(parsed) && parsed > 0
    ? Math.min(parsed, MAX_TIMEOUT_MS)
    : DEFAULT_TIMEOUT_MS;
    
  let fallbackUrl;
  try {
    fallbackUrl = new URL(getEnv('FALLBACK_URL', env) || DEFAULT_FALLBACK).toString();
  } catch {
    fallbackUrl = DEFAULT_FALLBACK;
  }
  
  return { ids, primaryTimeoutMs, fallbackUrl };
}

function parsePath(clientUrl, env) {
  if (PLATFORM === 'cloudflare') {
    const normalizedBase = (getEnv('BASE_PATH', env) || '').replace(/^\/+|\/+$/g, '');
    const basePath = normalizedBase ? `/${normalizedBase}` : '/dns-query';
    if (clientUrl.pathname !== basePath && !clientUrl.pathname.startsWith(basePath + '/')) {
      return { error: 'Not Found', status: 404 };
    }
    return { devicePath: safeDecodePath(clientUrl.pathname.substring(basePath.length)) };
  }
  
  const mountPath = (getEnv('MOUNT_PATH', env) || '').replace(/^\/+|\/+$/g, '');
  const basePath  = `/${mountPath || 'uimak'}`;
  if (clientUrl.pathname !== basePath && !clientUrl.pathname.startsWith(basePath + '/')) {
    return { error: 'Not Found', status: 404 };
  }
  const devicePath = PLATFORM === 'vercel'
    ? safeDecodePath(clientUrl.searchParams.get('__path') || '')
    : safeDecodePath(clientUrl.pathname.slice(basePath.length));
    
  return { devicePath };
}

async function parseDnsRequest(request, clientUrl) {
  if (request.method === 'GET') {
    const dnsParam = clientUrl.searchParams.get('dns');
    if (!dnsParam) return { response: errResp('Missing dns parameter', 400) };
    // base64url 编码比原始数据膨胀约 4/3 倍；设置与 POST MAX_BODY 等价的上限，
    // 防止超大参数触发昂贵的正则扫描和内存分配（与 POST 分支的双重校验保持对称）
    if (dnsParam.length > Math.ceil(MAX_BODY * 4 / 3) + 4) {
      return { response: errResp('Payload Too Large', 413) };
    }
    try {
      return { wire: base64urlDecode(dnsParam) };
    } catch (e) {
      console.warn('Invalid base64url in GET request:', e.message);
      return { response: errResp('Invalid dns parameter', 400) };
    }
  }
  
  const ct = request.headers.get('Content-Type') || '';
  if (!ct.startsWith('application/dns-message')) {
    return { response: errResp('Unsupported Media Type', 415) };
  }
  
  const cl = request.headers.get('Content-Length');
  if (cl !== null) {
    const clNum = parseInt(cl, 10);
    if (!Number.isFinite(clNum) || clNum < 0) {
      return { response: errResp('Bad Request', 400) };
    }
    if (clNum > MAX_BODY) {
      return { response: errResp('Payload Too Large', 413) };
    }
  }
  
  try {
    const buf = await request.arrayBuffer();
    if (buf.byteLength > MAX_BODY) return { response: errResp('Payload Too Large', 413) };
    return { wire: new Uint8Array(buf) };
  } catch (e) {
    console.warn('Failed to read request body:', e.message);
    return { response: errResp('Failed to read request body', 400) };
  }
}

// buildResponse 是纯函数，与请求上下文无关，提升为模块级以避免每次请求重复分配
const buildResponse = ({ body, status, statusText, headers }) =>
  new Response(body, { status, statusText, headers });

// tryFetch 是纯函数（不依赖任何请求上下文），提升为模块级以避免每次请求重复分配函数对象
const tryFetch = async (upstreamUrl, wire, signal) => {
  const req = new Request(upstreamUrl, {
    method: 'POST',
    headers: UPSTREAM_HEADERS,
    body: wire,
    redirect: 'follow',
    signal,
  });
  const response = await fetch(req);
  if (response.status >= 500) {
    // 取消读取 body 以释放资源，避免读入可能较大的错误响应体
    await response.body?.cancel();
    throw createCustomError('UpstreamError', `Upstream error: ${response.status}`);
  }

  const contentLength = response.headers.get('Content-Length');
  if (contentLength) {
    const len = parseInt(contentLength, 10);
    if (Number.isFinite(len) && len > MAX_RESPONSE) {
      throw createCustomError('ResponseTooLargeError', `Response too large: ${len} bytes`);
    }
  }

  const body = await response.arrayBuffer();
  if (body.byteLength > MAX_RESPONSE) {
    throw createCustomError('ResponseTooLargeError', `Response too large: ${body.byteLength} bytes`);
  }

  const respHeaders = new Headers(response.headers);
  respHeaders.delete('Transfer-Encoding');
  respHeaders.delete('Content-Encoding');
  respHeaders.set('Content-Length', body.byteLength.toString());
  respHeaders.set('X-Proxied-By', `NextDNS-Proxy/${capitalize(PLATFORM)}`);
  respHeaders.set('Access-Control-Allow-Origin', '*');
  return { body, status: response.status, statusText: response.statusText, headers: respHeaders };
};

// ================================================================
// 核心请求处理
// ================================================================

async function handleRequest(request, env, context) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (!ALLOWED_METHODS.has(request.method)) {
    return errResp('Method Not Allowed', 405);
  }

  const config = parseConfig(env);
  if ('error' in config) return errResp(config.error, 500);

  const clientUrl = new URL(request.url);
  const pathResult = parsePath(clientUrl, env);
  if ('error' in pathResult) return errResp(pathResult.error, pathResult.status);

  const dnsResult = await parseDnsRequest(request, clientUrl);
  if ('response' in dnsResult) return dnsResult.response;
  const { wire: dnsWire } = dnsResult;

  if (dnsWire.length < DNS_CONSTANTS.HEADER_SIZE) return errResp('Invalid DNS message', 400);

  // parseIp 只调用一次，结果复用于公网检测和 ECS 注入，消除双重解析
  const parsedClientIP = parseIp(getClientIP(request.headers, context));
  let mutatedWire = dnsWire;
  if (isPublicParsedIp(parsedClientIP)) {
    try {
      mutatedWire = injectECS(dnsWire, parsedClientIP);
    } catch (e) {
      console.warn('Failed to inject ECS:', e.message);
    }
  }

  const selectedId  = config.ids[Math.floor(Math.random() * config.ids.length)];
  const primaryUrl  = new URL(`${NEXTDNS_BASE}/${selectedId}${encodeDevicePath(pathResult.devicePath)}`);

  try {
    const result = await withTimeout(signal => tryFetch(primaryUrl, mutatedWire, signal), config.primaryTimeoutMs);
    return buildResponse(result);
  } catch (primaryErr) {
    console.warn('Primary upstream failed:', primaryErr.message);
    try {
      const result = await withTimeout(signal => tryFetch(config.fallbackUrl, mutatedWire, signal), FALLBACK_TIMEOUT_MS);
      result.headers.set('X-Fallback', primaryErr.name === 'TimeoutError' ? 'primary-timeout' : 'primary-error');
      return buildResponse(result);
    } catch (fallbackErr) {
      console.error('Both primary and fallback failed:', fallbackErr.message);
      return errResp('Bad Gateway', 502);
    }
  }
}

// ================================================================
// 平台导出（自动适配）
// ================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      console.error(`Unhandled error: ${err.name}: ${err.message}`, err.stack);
      return errResp('Internal Server Error', 500);
    }
  },
};

export async function onRequest(context) {
  try {
    return await handleRequest(context.request, context.env, context);
  } catch (err) {
    console.error(`Unhandled error: ${err.name}: ${err.message}`, err.stack);
    return errResp('Internal Server Error', 500);
  }
}

export const config = { runtime: 'edge' };
