const NEXTDNS_BASE     = 'https://dns.nextdns.io';
const DEFAULT_FALLBACK = 'https://dns.google/dns-query';
const MAX_BODY         = 64 * 1024;

const withTimeout = (fetchFn, ms) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetchFn(controller.signal)
    .finally(() => clearTimeout(timer))
    .catch(err => {
      if (err.name === 'AbortError') {
        const e = new Error('Timeout');
        e.name = 'TimeoutError';
        throw e;
      }
      throw err;
    });
};

const maskIP = (ip) => {
  if (ip.includes(':')) {
    const sections = ip.split(':');
    const missing  = 8 - sections.filter(s => s !== '').length;
    const full     = ip.replace('::', ':' + '0:'.repeat(missing)).replace(/^:|:$/g, '');
    return full.split(':').slice(0, 3).join(':') + '::/48';
  } else {
    return ip.split('.').slice(0, 3).join('.') + '.0/24';
  }
};

async function handleRequest(request, env) {
  const clientUrl = new URL(request.url);

  // 按逗号分割，支持多个 ID 随机负载均衡
  const NEXTDNS_IDS        = (env.NEXTDNS_ID ?? '').split(',').map(s => s.trim()).filter(Boolean);
  const BASE_PATH          = env.BASE_PATH ?? '';
  const PRIMARY_TIMEOUT_MS = (() => {
    const n = parseInt(env.TIMEOUT_MS, 10);
    return Number.isFinite(n) && n > 0 ? n : 2500;
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

  // 提前构建好 Headers，主备上游复用同一份，避免重复计算
  // 只追加 cfIP，避免把从 XFF 读出来的 IP 再写回去造成重复
  const headers = new Headers(request.headers);
  if (cfIP) {
    headers.set(
      'X-Forwarded-For',
      xffHeader ? `${xffHeader}, ${cfIP}` : cfIP
    );
  }
  headers.delete('CF-Connecting-IP');
  headers.delete('CF-Ray');
  headers.delete('CF-Visitor');
  headers.delete('CF-IPCountry');

  const hasBody = !['GET', 'HEAD'].includes(request.method);
  let body = null;
  if (hasBody) {
    // 超过 64KB 直接拒绝，符合 DNS 消息最大长度，防止异常大请求
    const cl = request.headers.get('Content-Length');
    if (cl && parseInt(cl, 10) > MAX_BODY) {
      return new Response('Payload Too Large', { status: 413 });
    }
    try {
      body = await request.arrayBuffer();
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
    const response    = await fetch(req);
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
    // 主上游失败，切备用（备用同样有超时控制）
    try {
      const resp        = await withTimeout(
        (signal) => tryFetch(fallbackUrl.toString(), signal),
        PRIMARY_TIMEOUT_MS
      );
      const respHeaders = new Headers(resp.headers);
      respHeaders.set('X-Fallback', primaryErr.name === 'TimeoutError' ? 'primary-timeout' : 'primary-error');
      return new Response(resp.body, {
        status:     resp.status,
        statusText: resp.statusText,
        headers:    respHeaders,
      });
    } catch (err) {
      return new Response(`Bad Gateway: ${err.message}`, { status: 502 });
    }
  }
}

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  }
};
