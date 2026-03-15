const NEXTDNS_BASE        = 'https://dns.nextdns.io';
const DEFAULT_FALLBACK    = 'https://dns.google/dns-query';
const MAX_BODY            = 64 * 1024; // 64KB，符合 DNS 消息最大长度标准
const DEFAULT_TIMEOUT_MS  = 2500;      // 主上游默认超时时间（毫秒）
const FALLBACK_TIMEOUT_MS = 1500;      // 备用上游超时时间（毫秒）

// async/await + try/finally 确保 timer 在任何情况下都会被清除
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

const maskIP = (ip) => {
  if (ip.includes(':')) {
    // IPv4-mapped IPv6 地址（::ffff:x.x.x.x），提取内嵌 IPv4 处理
    if (ip.toLowerCase().includes('::ffff:')) {
      const v4 = ip.split(':').pop();
      return v4 && v4.includes('.') ? maskIP(v4) : null;
    }
    // 用 split('::') 展开压缩形式，比字符串替换更可靠
    const parts = ip.split('::');
    const left  = parts[0] ? parts[0].split(':') : [];
    const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    const zeros = Array(8 - left.length - right.length).fill('0');
    const full  = [...left, ...zeros, ...right];
    // 符合 RFC 5952，压缩前导零（如 0db8 → db8）
    const prefix = full.slice(0, 3).map(p => p.replace(/^0+/, '') || '0');
    return prefix.join(':') + '::/48';
  }
  return ip.split('.').slice(0, 3).join('.') + '.0/24';
};

async function handleRequest(request, env) {
  const clientUrl = new URL(request.url);

  // DoH 只允许 GET 和 POST
  if (!['GET', 'POST'].includes(request.method)) {
    return new Response('Method Not Allowed', { status: 405 });
  }

  // 按逗号分割，支持多个 ID 随机负载均衡
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

  // FALLBACK_URL 格式校验，非法时自动回落默认值
  let fallbackUrl;
  try {
    fallbackUrl = new URL(env.FALLBACK_URL || DEFAULT_FALLBACK);
  } catch {
    fallbackUrl = new URL(DEFAULT_FALLBACK);
  }

  // 直接访问：只有 CF-Connecting-IP
  // 套了外层 CDN：X-Forwarded-For 第一个 IP 才是真实客户端 IP
  const cfIP      = request.headers.get('CF-Connecting-IP');
  const xffHeader = request.headers.get('X-Forwarded-For');
  const xffIP     = xffHeader ? xffHeader.split(',')[0].trim() : null;
  const clientIP  = xffIP || cfIP;

  const clientSubnet = clientIP ? maskIP(clientIP) : null;

  // 构建转发给上游的请求头
  const headers = new Headers(request.headers);
  // 直连时 XFF 为空，追加 cfIP（即用户真实 IP）
  // 套了 CDN 时 XFF 已包含用户真实 IP，保持原样不追加，避免重复
  if (!xffHeader && cfIP) {
    headers.set('X-Forwarded-For', cfIP);
  }
  headers.delete('CF-Connecting-IP');
  headers.delete('CF-Ray');
  headers.delete('CF-Visitor');
  headers.delete('CF-IPCountry');

  const hasBody = request.method === 'POST';
  let body = null;
  if (hasBody) {
    // 先检查 Content-Length 快速拦截，再验证实际大小防止伪造
    const cl = request.headers.get('Content-Length');
    if (cl && parseInt(cl, 10) > MAX_BODY) {
      return new Response('Payload Too Large', { status: 413 });
    }
    try {
      body = await request.arrayBuffer();
      if (body.byteLength > MAX_BODY) {
        return new Response('Payload Too Large', { status: 413 });
      }
    } catch {
      return new Response('Failed to read request body', { status: 400 });
    }
  }

  const tryFetch = async (upstreamUrl, signal) => {
    const req = new Request(upstreamUrl, {
      method:   request.method,
      headers,
      body:     hasBody ? body : null,
      redirect: 'follow',
      signal,
    });
    const response = await fetch(req);
    // 上游返回 5xx 时抛异常，触发切换备用上游
    if (response.status >= 500) {
      const err = new Error(`Upstream error: ${response.status}`);
      err.name = 'UpstreamError';
      throw err;
    }
    const respHeaders = new Headers(response.headers);
    respHeaders.set('X-Proxied-By', 'CF-Worker-NextDNS');
    return new Response(response.body, {
      status:     response.status,
      statusText: response.statusText,
      headers:    respHeaders,
    });
  };

  const devicePath = clientUrl.pathname.substring(basePath.length);

  // 随机选一个 NextDNS ID，多个 ID 时概率均等分摊额度
  const selectedId  = NEXTDNS_IDS[Math.floor(Math.random() * NEXTDNS_IDS.length)];
  const primaryUrl  = new URL(`${NEXTDNS_BASE}/${selectedId}${devicePath}`);
  primaryUrl.search = clientUrl.search;
  if (clientSubnet) {
    primaryUrl.searchParams.set('ci', clientSubnet);
  }

  // 备用上游 ECS（只有 Google DoH 支持 URL 参数传 ECS）
  fallbackUrl.search = clientUrl.search;
  if (clientSubnet && fallbackUrl.hostname === 'dns.google') {
    fallbackUrl.searchParams.set('edns_client_subnet', clientSubnet);
  }

  try {
    return await withTimeout(
      (signal) => tryFetch(primaryUrl.toString(), signal),
      PRIMARY_TIMEOUT_MS
    );
  } catch (primaryErr) {
    // 主上游失败（超时、网络错误、5xx），切备用
    try {
      const resp        = await withTimeout(
        (signal) => tryFetch(fallbackUrl.toString(), signal),
        FALLBACK_TIMEOUT_MS
      );
      const respHeaders = new Headers(resp.headers);
      respHeaders.set('X-Fallback', primaryErr.name === 'TimeoutError' ? 'primary-timeout' : 'primary-error');
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
