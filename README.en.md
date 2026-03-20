# NextDNS Cloudflare Worker Proxy

**English | [中文](https://github.com/QSDR2s1d/NextDNS-Cloudflare-Worker/blob/main/README.md)**

A Cloudflare Worker reverse proxy for NextDNS DoH, with support for custom paths, fallback upstream, ECS forwarding, and automatic timeout switching.

## Features

- 🔒 **Hidden path authentication**: Custom DoH path — requests without the correct path get a 404
- 🌍 **ECS forwarding**: Automatically passes the client's real IP subnet to upstream, ensuring geographically accurate DNS responses
- 🔄 **Automatic fallback**: Switches to a backup DoH server on timeout or error
- ⏱️ **Timeout control**: Uses `AbortController` to truly abort timed-out requests, avoiding wasted resources
- ⚙️ **Fully environment-variable-driven**: No code changes needed — all settings are controlled via environment variables

## Deployment

### 1. Create a Worker

Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com), go to **Workers & Pages → Create application → Create Worker**, paste the contents of `worker.js`, then save and deploy.

### 2. Configure environment variables

Go to your Worker's **Settings → Variables** and add the following:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXTDNS_ID` | ✅ Yes | — | Your NextDNS configuration ID, found on the Setup page of your NextDNS dashboard |
| `BASE_PATH` | Optional | `dns-query` | Custom path to hide your DoH endpoint. Setting `mysecretpath` makes your endpoint `/mysecretpath` |
| `FALLBACK_URL` | Optional | `https://dns.google/dns-query` | Backup DoH server used when the primary is unavailable |
| `TIMEOUT_MS` | Optional | `2500` | Primary upstream timeout in milliseconds before switching to fallback |

### 3. Configure DoH on your device

After deploying, your DoH URL will be:

```
https://<your-worker-name>.<your-subdomain>.workers.dev/<BASE_PATH>
```

For example:

```
https://nextdns-proxy.example.workers.dev/mysecretpath
```

Enter this URL in the DoH settings of your device, router, or browser.

## How it works

```
Device sends DNS request
         ↓
Cloudflare Worker receives request
         ↓
Extracts real client IP (X-Forwarded-For or CF-Connecting-IP)
Generates /24 (IPv4) or /48 (IPv6) subnet mask
         ↓
Forwards to NextDNS (with ECS subnet parameter ?ci=)
         ↓
Timeout or error? → Automatically switch to fallback DoH
         ↓
Returns DNS response to device
```

## ECS details

ECS (EDNS Client Subnet) tells the DNS server the client's approximate location, so it can return the geographically optimal CDN node.

How this Worker handles ECS:

- **NextDNS**: Passes the client IP subnet via the `?ci=` parameter (officially supported)
- **Google DoH** (default fallback): Passes via the `?edns_client_subnet=` parameter
- **Other fallback servers**: No ECS parameter is sent, to avoid compatibility issues

To protect privacy, only the IP subnet is sent, not the full IP:

- IPv4: `/24`, e.g. `1.2.3.0/24`
- IPv6: `/48`, e.g. `2001:db8:1::/48`

## CDN compatibility

If you place another CDN in front of this Worker, the Worker will automatically detect the client's real IP from `X-Forwarded-For` (set by the CDN). If no `X-Forwarded-For` header is present (direct access), it falls back to `CF-Connecting-IP`. No configuration changes are needed for either scenario.

## Response headers

| Header | Description |
|--------|-------------|
| `X-Proxied-By: CF-Worker-NextDNS` | Indicates the request was proxied through this Worker |
| `X-Fallback: primary-timeout` | Primary upstream timed out, switched to fallback |
| `X-Fallback: primary-error` | Primary upstream errored, switched to fallback |

## FAQ

**Q: Is it safe to leave `BASE_PATH` unset?**

The default path `/dns-query` is the standard DoH path and easy to guess. It is recommended to set a random string as your custom path (e.g. `dns-a8f3kz2q`) to obscure your endpoint.

**Q: Where do I find my `NEXTDNS_ID`?**

Log in to the [NextDNS dashboard](https://my.nextdns.io), open your configuration, and go to the **Setup** page. Your DoH URL will be shown there — the last segment is your ID. For example, in `https://dns.nextdns.io/a1b2c3`, the ID is `a1b2c3`.

**Q: What can I use as a fallback DoH server?**

Any standard DoH URL works, for example:

- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Quad9: `https://dns.quad9.net/dns-query`
- AdGuard: `https://dns.adguard.com/dns-query`

Note: ECS parameters are only forwarded when the fallback is Google DoH. Other providers do not receive ECS data.

**Q: Is the free Cloudflare Workers plan enough?**

Yes. The free plan includes 100,000 requests per day, which is more than sufficient for personal use.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/QSDR2s1d/NextDNS-Cloudflare-Worker)
