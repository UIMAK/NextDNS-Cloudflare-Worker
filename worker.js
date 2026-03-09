const NEXTDNS_BASE     = 'https://dns.nextdns.io';
const DEFAULT_FALLBACK = 'https://dns.google/dns-query';

const withTimeout = (fetchFn, ms) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetchFn(controller.signal).finally(() => clearTimeout(timer));
};

const maskIP = (ip) => {
  if (ip.includes(':')) {
    const sections = ip.split(':');
    const missing  = 8 - sections.filter(s => s !== '').length;
    const full     = ip.replace('::', ':' + '0:'.repeat(missing)).replace(/^:|:$/, '');
    return full.split(':').slice(0, 3).join(':') + '::/48';
  } else {
    return ip.split('.').slice(0, 3).join('.') + '.0/24';
  }
};

async function handleRequest(request, env) {
  const clientUrl = new URL(request.url);

  // 按逗号分割，支持多个 ID 随机负载均衡
  const NEXTDNS_IDS        = (env.NEXTDNS_ID ?? '').split(',').map(s => s.trim()).filter(Boolean);
  const BASE_PATH          = env.BASE_PATH    ?? '';
  const FALLBACK_URL       = env.FALLBACK_URL ?? '';
  const PRIMARY_TIMEOUT_MS = parseInt(env.TIMEOUT_MS) || 2500;

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

  const cfIP      = request.headers.get('CF-Connecting-IP');
  const xffHeader = request.headers.get('X-Forwarded-For');
  const xffIP     = xffHeader ? xffHeader.split(',')[0].trim() : null;
  const clientIP  = xffIP || cfIP;

  const clientSubnet = clientIP ? maskIP(clientIP) : null;

  const buildHeaders = () => {
    const newHeaders = new Headers(request.headers);
    if (clientIP) {
      const existingXFF = request.headers.get('X-Forwarded-For');
      newHeaders.set(
        'X-Forwarded-For',
        existingXFF ? `${existingXFF}, ${clientIP}` : clientIP
      );
    }
    newHeaders.delete('CF-Connecting-IP');
    newHeaders.delete('CF-Ray');
    newHeaders.delete('CF-Visitor');
    newHeaders.delete('CF-IPCountry');
    return newHeaders;
  };

  const hasBody = !['GET', 'HEAD'].includes(request.method);
  let body = null;
  if (hasBody) {
    try {
      body = await request.arrayBuffer();
    } catch {
      return new Response('Failed to read request body', { status: 400 });
    }
  }

  const tryFetch = async (upstreamUrl, signal) => {
    const req = new Request(upstreamUrl, {
      method:   request.method,
      headers:  buildHeaders(),
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

  // 随机选一个 ID，多个 ID 时概率均等分摊额度
  const selectedId  = NEXTDNS_IDS[Math.floor(Math.random() * NEXTDNS_IDS.length)];
  const primaryUrl  = new URL(`${NEXTDNS_BASE}/${selectedId}${devicePath}`);
  primaryUrl.search = clientUrl.search;
  if (clientSubnet) {
    primaryUrl.searchParams.set('ci', clientSubnet);
  }

  // 备用上游
  const fallbackUrl  = new URL(FALLBACK_URL || DEFAULT_FALLBACK);
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
    try {
      const resp    = await tryFetch(fallbackUrl.toString());
      const headers = new Headers(resp.headers);
      headers.set('X-Fallback', primaryErr.name === 'AbortError' ? 'primary-timeout' : 'primary-error');
      return new Response(resp.body, {
        status:     resp.status,
        statusText: resp.statusText,
        headers,
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
