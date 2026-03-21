# NextDNS Cloudflare Worker Proxy

**English | [中文](https://github.com/QSDR2s1d/NextDNS-Cloudflare-Worker/blob/main/README.md)**

A Cloudflare Worker reverse proxy for NextDNS DoH, with support for custom paths, fallback upstream, DNS-level ECS injection, and automatic timeout switching.

## Features

- 🔒 **Hidden path authentication**: Custom DoH path — requests without the correct path get a 404
- 🌍 **DNS-level ECS injection**: Injects EDNS Client Subnet directly into the DNS wire format, compliant with RFC 7871, works with any ECS-capable upstream
- 🔄 **Automatic fallback**: Switches to a backup DoH server on timeout or error
- ⚖️ **Multi-account load balancing**: Supports multiple NextDNS IDs, randomly distributing requests to share quota
- ⏱️ **Timeout control**: Uses `AbortController` to truly abort timed-out requests, avoiding wasted resources
- ⚙️ **Fully environment-variable-driven**: No code changes needed — all settings are controlled via environment variables
- 🌐 **CORS support**: Supports direct browser calls, compatible with web-based DoH testing tools

## Deployment

### 1. Create a Worker

Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com), go to **Workers & Pages → Create application → Create Worker**, paste the contents of `worker.js`, then save and deploy.

### 2. Configure environment variables

Go to your Worker's **Settings → Variables** and add the following:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NEXTDNS_ID` | ✅ Yes | — | Your NextDNS configuration ID. Multiple IDs can be separated by commas, e.g. `a1b2c3,d4e5f6` |
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

NextDNS supports appending a device name to the path for identification in logs:

```
https://nextdns-proxy.example.workers.dev/mysecretpath/my-phone
```

## How it works

```
Device sends DNS request (GET or POST)
         ↓
Cloudflare Worker receives request
         ↓
Extracts real client IP from request headers
(Priority: EO-Client-IP → ali-real-client-ip → CF-Connecting-IP → X-Forwarded-For → X-Real-IP)
         ↓
Decodes DNS wire format, injects ECS at binary level
(IPv4: /24 subnet, IPv6: /48 subnet, private IPs are not injected)
         ↓
Converts to POST and forwards to a randomly selected NextDNS upstream
         ↓
Timeout or error? → Automatically switch to fallback DoH
         ↓
Returns DNS response to device
```

## ECS details

ECS (EDNS Client Subnet) tells the DNS server the client's approximate location, so it can return the geographically optimal CDN node.

This Worker uses **DNS wire-level injection**, writing the ECS option directly into the binary DNS message, compliant with RFC 7871. Compared to URL parameter approaches, this is more universal and works with any ECS-capable DoH upstream without per-provider adaptation.

To protect privacy, only the IP subnet is sent, not the full IP:

- IPv4: `/24`, e.g. `1.2.3.0/24`
- IPv6: `/48`, e.g. `2001:db8:1::/48`
- Private IPs (192.168.x.x, 10.x.x.x, etc.) are not injected

## CDN compatibility

If you place another CDN in front of this Worker, it will automatically detect the real client IP using the following priority order:

| Priority | Header | Use case |
|----------|--------|----------|
| 1 | `EO-Client-IP` | Tencent EdgeOne |
| 2 | `ali-real-client-ip` | Alibaba Cloud CDN |
| 3 | `CF-Connecting-IP` | Direct Cloudflare access |
| 4 | `X-Forwarded-For` | Generic proxy (first value) |
| 5 | `X-Real-IP` | Generic fallback |

No additional configuration needed — both direct access and CDN-proxied scenarios are handled automatically.

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

**Q: How do I configure multiple NextDNS IDs to share quota?**

Set multiple IDs separated by commas in the `NEXTDNS_ID` variable, e.g. `a1b2c3,d4e5f6`. Each request randomly selects one ID, so two IDs each handle ~50% of traffic, and so on.

**Q: What can I use as a fallback DoH server?**

Any standard DoH URL works, for example:

- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Quad9: `https://dns.quad9.net/dns-query`
- AdGuard: `https://dns.adguard.com/dns-query`

All ECS-capable fallback upstreams will automatically receive ECS injection — no extra configuration needed.

**Q: Is the free Cloudflare Workers plan enough?**

Yes. The free plan includes 100,000 requests per day, which is more than sufficient for personal use.

**Q: Can this be deployed to Cloudflare Pages?**

Yes. Place the file at `functions/[[path]].js` — no code changes are needed. The same file is compatible with both Worker and Pages Functions deployments.

## License

MIT

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/QSDR2s1d/NextDNS-Cloudflare-Worker)
