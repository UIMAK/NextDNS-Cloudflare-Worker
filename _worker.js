// 环境变量配置 ：
	//   NEXTDNS_ID   : 你的 NextDNS 配置 ID（必填），多个用逗号分隔
	//   BASE_PATH    : 自定义路径前缀，不填默认 dns-query
	//   FALLBACK_URL : 备用 DoH，不填默认 https://dns.google/dns-query
	//   TIMEOUT_MS   : 主上游超时时间（毫秒），不填默认 2500
	// ================================================================
	 
	const NEXTDNS_BASE        = 'https://dns.nextdns.io';
	const DEFAULT_FALLBACK    = 'https://dns.google/dns-query';
	const MAX_BODY            = 64 * 1024;
	const DEFAULT_TIMEOUT_MS  = 2500;
	const FALLBACK_TIMEOUT_MS = 1500;
	const ECS_V4_PREFIX       = 24;
	const ECS_V6_PREFIX       = 48;
	 
	const CORS_HEADERS = {
	  'Access-Control-Allow-Origin':  '*',
	  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	  'Access-Control-Allow-Headers': 'Content-Type, Accept',
	  'Access-Control-Max-Age':       '86400',
	};
	 
	const UPSTREAM_HEADERS = Object.freeze({
	  'Content-Type': 'application/dns-message',
	  'Accept':       'application/dns-message',
	});
	 
	const CDN_IP_HEADERS = [
	  'EO-Client-IP', 'ali-real-client-ip', 'CF-Connecting-IP',
	  'X-Forwarded-For', 'X-Real-IP',
	];
	 
	const errResp = (body, status) =>
	  new Response(body, { status, headers: CORS_HEADERS });
	 
	let _config = null;
	function getConfig(env) {
	  if (_config) return _config;
	  const NEXTDNS_IDS = (env.NEXTDNS_ID ?? '')
	    .split(',')
	    .map(s => s.trim().replace(/[^a-zA-Z0-9_-]/g, ''))
	    .filter(Boolean);
	  const PRIMARY_TIMEOUT_MS = (() => {
	    const n = parseInt(env.TIMEOUT_MS, 10);
	    return Number.isFinite(n) && n > 0 ? n : DEFAULT_TIMEOUT_MS;
	  })();
	  let fallbackBase = DEFAULT_FALLBACK;
	  try { fallbackBase = new URL(env.FALLBACK_URL || DEFAULT_FALLBACK).toString(); } catch {}
	  const normalizedBase = (env.BASE_PATH ?? '').replace(/^\/+|\/+$/g, '');
	  const basePath = normalizedBase ? `/${normalizedBase}` : '/dns-query';
	  _config = { NEXTDNS_IDS, PRIMARY_TIMEOUT_MS, fallbackBase, basePath };
	  return _config;
	}
	 
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
	 
	const getClientIP = (headers) => {
	  for (const name of CDN_IP_HEADERS) {
	    const val = headers.get(name);
	    if (!val) continue;
	    const ip = val.split(',')[0].trim().replace(/^\[|\]$/g, '');
	    if (ip) return ip;
	  }
	  return null;
	};
	 
	const safeDecodePath = (raw) => {
	  if (!raw || raw === '/') return '';
	  try {
	    let prev, curr = raw;
	    do {
	      prev = curr;
	      curr = decodeURIComponent(curr);
	    } while (curr !== prev);
	    const cleaned = curr
	      .replace(/^\/+/, '')
	      .split('/')
	      .filter(seg => seg !== '' && !seg.startsWith('.'))
	      .join('/');
	    return cleaned ? '/' + cleaned : '';
	  } catch {
	    return '';
	  }
	};
	 
	const encodeDevicePath = (devicePath) =>
	  devicePath.split('/').map(seg => encodeURIComponent(seg)).join('/');
	 
	function base64urlDecode(s) {
	  if (s.length % 4 === 1) throw new Error('Invalid base64url length');
	  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('Invalid base64url characters');
	  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
	  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
	  const bin = atob(b64);
	  return Uint8Array.from(bin, c => c.charCodeAt(0));
	}
	 
	function readU16(buf, off) {
	  if (off + 1 >= buf.length) throw new RangeError('readU16 out of bounds');
	  return (buf[off] << 8) | buf[off + 1];
	}
	 
	function writeU16BE(value) { return new Uint8Array([value >> 8, value & 0xff]); }
	 
	function skipName(buf, off) {
	  let o = off;
	  let steps = 0;
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
	  return o;
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
	  return endName + 10 + readU16(buf, endName + 8);
	}
	 
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
	 
	  const optRecord = concatUint8(
	    new Uint8Array([0x00]), writeU16BE(41), writeU16BE(4096),
	    new Uint8Array([0, 0, 0, 0]), writeU16BE(ecsOpt.length), ecsOpt
	  );
	  const newBuf = concatUint8(buf, optRecord);
	  const ar2 = ar + 1;
	  newBuf[10] = (ar2 >> 8) & 0xff;
	  newBuf[11] = ar2 & 0xff;
	  return newBuf;
	}
	 
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
	 
	const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;
	 
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
	  if (left.some(h => !HEX_GROUP.test(h)) || right.some(h => !HEX_GROUP.test(h))) return null;
	  const leftVals  = left.map(h => parseInt(h, 16));
	  const rightVals = right.map(h => parseInt(h, 16));
	  if (leftVals.some(Number.isNaN) || rightVals.some(Number.isNaN)) return null;
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
	 
	function allZero(buf, start, end) {
	  for (let i = start; i < end; i++) if (buf[i] !== 0) return false;
	  return true;
	}
	 
	function isPublicIPv4(ip) {
	  const b = parseIPv4(ip);
	  if (!b) return false;
	  const n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
	  const inRange = (base, mask) => (n & mask) >>> 0 === (base >>> 0);
	  return !(
	    inRange(0x0a000000, 0xff000000) || inRange(0xac100000, 0xfff00000) ||
	    inRange(0xc0a80000, 0xffff0000) || inRange(0x7f000000, 0xff000000) ||
	    inRange(0xa9fe0000, 0xffff0000) || inRange(0x64400000, 0xffc00000) ||
	    inRange(0x00000000, 0xff000000) || (b[0] & 0xf0) === 0xe0 || (b[0] & 0xf0) === 0xf0
	  );
	}
	 
	function isPublicIPv6(ip) {
	  const b = parseIPv6(ip);
	  if (!b) return false;
	  const [b0, b1, b2, b3] = b;
	  const isV4Mapped = allZero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff;
	  const isNAT64 = b0 === 0x00 && b1 === 0x64 && b2 === 0xff && b3 === 0x9b && allZero(b, 4, 12);
	  const isLocalNAT64 = b0 === 0x00 && b1 === 0x64 && b2 === 0xff && b3 === 0x9b && b[4] === 0x00 && b[5] === 0x01;
	  const is6to4 = b0 === 0x20 && b1 === 0x02;
	 
	  if (isV4Mapped || isNAT64 || isLocalNAT64 || is6to4) {
	    const v4 = is6to4 ? `${b[2]}.${b[3]}.${b[4]}.${b[5]}` : `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
	    return isPublicIPv4(v4);
	  }
	 
	  return !(
	    allZero(b, 0, 16) || (allZero(b, 0, 15) && b[15] === 1) ||
	    (b0 & 0xfe) === 0xfc || (b0 === 0xfe && (b1 & 0xc0) === 0x80) ||
	    b0 === 0xff || (b0 === 0x20 && b1 === 0x01 && b2 === 0x0d && b3 === 0xb8) ||
	    (b0 === 0x20 && b1 === 0x01 && b2 === 0x00 && (b3 & 0xf0) === 0x10) ||
	    (b0 === 0x20 && b1 === 0x01 && b2 === 0x00 && (b3 & 0xf0) === 0x20)
	  );
	}
	 
	function isPublicIp(ip) {
	  if (!ip) return false;
	  return ip.includes(':') ? isPublicIPv6(ip) : isPublicIPv4(ip);
	}
	 
	async function handleRequest(request, env) {
	  const clientUrl = new URL(request.url);
	 
	  if (request.method === 'OPTIONS') {
	    return new Response(null, { status: 204, headers: CORS_HEADERS });
	  }
	 
	  if (!['GET', 'POST'].includes(request.method)) {
	    return errResp('Method Not Allowed', 405);
	  }
	 
	  const { NEXTDNS_IDS, PRIMARY_TIMEOUT_MS, fallbackBase, basePath } = getConfig(env);
	 
	  if (
	    clientUrl.pathname !== basePath &&
	    !clientUrl.pathname.startsWith(basePath + '/')
	  ) {
	    return errResp('Not Found', 404);
	  }
	 
	  if (NEXTDNS_IDS.length === 0) {
	    return errResp('Server misconfiguration: NEXTDNS_ID not set', 500);
	  }
	 
	  const clientIP = getClientIP(request.headers);
	 
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
	    const ct = request.headers.get('Content-Type') || '';
	    if (!ct.startsWith('application/dns-message')) {
	      return errResp('Unsupported Media Type', 415);
	    }
	    const cl = request.headers.get('Content-Length');
	    if (cl !== null) {
	      const clNum = parseInt(cl, 10);
	      if (!Number.isInteger(clNum) || clNum < 0 || clNum > MAX_BODY) {
	        return errResp('Payload Too Large', 413);
	      }
	    }
	    try {
	      const buf = await request.arrayBuffer();
	      if (buf.byteLength > MAX_BODY) return errResp('Payload Too Large', 413);
	      dnsWire = new Uint8Array(buf);
	    } catch {
	      return errResp('Failed to read request body', 400);
	    }
	  }
	 
	  if (dnsWire.length < 12) return errResp('Invalid DNS message', 400);
	 
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
	      method: 'POST', headers: UPSTREAM_HEADERS,
	      body: mutatedWire, redirect: 'follow', signal,
	    });
	    const response = await fetch(req);
	    if (response.status >= 500) {
	      const err = new Error(`Upstream error: ${response.status}`);
	      err.name = 'UpstreamError';
	      throw err;
	    }
	    const body = await response.arrayBuffer();
	    const respHeaders = new Headers(response.headers);
	    respHeaders.delete('Transfer-Encoding');
	    respHeaders.delete('Content-Encoding');
	    respHeaders.set('Content-Length', body.byteLength.toString());
	    respHeaders.set('X-Proxied-By', 'NextDNS-Proxy/Cloudflare');
	    respHeaders.set('Access-Control-Allow-Origin', '*');
	    return new Response(body, {
	      status: response.status,
	      statusText: response.statusText,
	      headers: respHeaders,
	    });
	  };
	 
	  const selectedId = NEXTDNS_IDS[Math.floor(Math.random() * NEXTDNS_IDS.length)];
	  const primaryUrl = new URL(`${NEXTDNS_BASE}/${selectedId}${encodeDevicePath(devicePath)}`);
	 
	  try {
	    return await withTimeout((signal) => tryFetch(primaryUrl, signal), PRIMARY_TIMEOUT_MS);
	  } catch (primaryErr) {
	    try {
	      const resp = await withTimeout((signal) => tryFetch(fallbackBase, signal), FALLBACK_TIMEOUT_MS);
	      const respHeaders = new Headers(resp.headers);
	      respHeaders.set('X-Fallback', primaryErr.name === 'TimeoutError' ? 'primary-timeout' : 'primary-error');
	      respHeaders.set('Access-Control-Allow-Origin', '*');
	      return new Response(resp.body, {
	        status: resp.status,
	        statusText: resp.statusText,
	        headers: respHeaders,
	      });
	    } catch {
	      return errResp('Bad Gateway', 502);
	    }
	  }
	}
	 
	export default {
	  async fetch(request, env) {
	    try {
	      return await handleRequest(request, env);
	    } catch (err) {
	      console.error(`Unhandled error: ${err.name}: ${err.message}`);
	      return new Response('Internal Server Error', { status: 500, headers: CORS_HEADERS });
	    }
	  }
	};
	 
	export async function onRequest(context) {
	  try {
	    return await handleRequest(context.request, context.env);
	  } catch (err) {
	    console.error(`Unhandled error: ${err.name}: ${err.message}`);
	    return new Response('Internal Server Error', { status: 500, headers: CORS_HEADERS });
	  }
	}
