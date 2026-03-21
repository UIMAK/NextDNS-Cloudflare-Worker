# NextDNS Cloudflare Worker 反代

**[English](https://github.com/QSDR2s1d/NextDNS-Cloudflare-Worker/blob/main/README.en.md) | 中文**

一个基于 Cloudflare Worker 的 NextDNS DoH 反向代理，支持自定义路径、备用上游、DNS 报文级 ECS 注入和超时自动切换。

## 功能特性

- 🔒 **隐藏路径鉴权**：自定义 DoH 路径，不知道路径的请求直接 404
- 🌍 **DNS 报文级 ECS 注入**：直接在 DNS 二进制报文中注入 EDNS Client Subnet，符合 RFC 7871 标准，对所有支持 ECS 的上游均有效
- 🔄 **自动 Fallback**：主上游超时或报错时自动切换备用 DoH
- ⚖️ **多账户负载均衡**：支持配置多个 NextDNS ID，随机分摊请求额度
- ⏱️ **超时控制**：使用 `AbortController` 真正中止超时请求，避免资源浪费
- ⚙️ **全环境变量配置**：无需修改代码，所有参数通过环境变量控制
- 🌐 **CORS 支持**：支持浏览器直接调用，兼容网页端 DoH 测试工具

## 部署

### 1. 创建 Worker

登录 [Cloudflare Dashboard](https://dash.cloudflare.com)，进入 **Workers & Pages → Create application → Create Worker**，将 `worker.js` 的内容粘贴进去，保存并部署。

### 2. 配置环境变量

进入 Worker 的 **Settings → Variables**，添加以下环境变量：

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `NEXTDNS_ID` | ✅ | 无 | 你的 NextDNS 配置 ID，多个 ID 用逗号分隔，如 `a1b2c3,d4e5f6` |
| `BASE_PATH` | — | `dns-query` | 自定义路径，用于隐藏你的 DoH 端点，填写 `mysecretpath` 则访问路径为 `/mysecretpath` |
| `FALLBACK_URL` | — | `https://dns.google/dns-query` | 主上游不可用时的备用 DoH 地址 |
| `TIMEOUT_MS` | — | `2500` | 主上游超时时间（毫秒），超时后自动切换备用 |

### 3. 在设备上配置 DoH

部署完成后，你的 DoH 地址为：

```
https://<your-worker-name>.<your-subdomain>.workers.dev/<BASE_PATH>
```

例如：

```
https://nextdns-proxy.example.workers.dev/mysecretpath
```

将此地址填入你的设备、路由器或浏览器的 DoH 设置中即可。

NextDNS 支持在路径后附加设备名称，用于在日志中区分不同设备：

```
https://nextdns-proxy.example.workers.dev/mysecretpath/my-phone
```

## 工作原理

```
设备发出 DNS 请求（GET 或 POST）
         ↓
Cloudflare Worker 接收请求
         ↓
从请求头提取真实客户端 IP
（优先级：EO-Client-IP → ali-real-client-ip → CF-Connecting-IP → X-Forwarded-For → X-Real-IP）
         ↓
解码 DNS 报文，在二进制层面注入 ECS
（IPv4 注入 /24 子网，IPv6 注入 /48 子网，私网 IP 不注入）
         ↓
统一转为 POST 转发至随机选中的 NextDNS 上游
         ↓
超时或报错？→ 自动切换备用 DoH
         ↓
返回 DNS 响应给设备
```

## ECS 说明

ECS（EDNS Client Subnet）让 DNS 服务器知道客户端大致位置，从而返回地理位置最优的 CDN 节点。

本 Worker 采用 **DNS 报文层注入**方式，直接在 DNS 二进制报文中写入 ECS option，符合 RFC 7871 标准。这与简单的 URL 参数方式相比更通用，对所有支持 ECS 的 DoH 上游均有效，无需针对每家服务商单独适配。

为保护隐私，只传递 IP 子网而非完整 IP：

- IPv4：注入 `/24`，如 `1.2.3.0/24`
- IPv6：注入 `/48`，如 `2001:db8:1::/48`
- 私网 IP（192.168.x.x、10.x.x.x 等）不注入 ECS

## CDN 兼容说明

如果在 Worker 前面套了外层 CDN，Worker 会按以下优先级自动识别真实客户端 IP：

| 优先级 | 请求头 | 适用场景 |
|--------|--------|----------|
| 1 | `EO-Client-IP` | 腾讯 EdgeOne |
| 2 | `ali-real-client-ip` | 阿里云 CDN |
| 3 | `CF-Connecting-IP` | 直连 Cloudflare |
| 4 | `X-Forwarded-For` | 通用代理（取第一个值） |
| 5 | `X-Real-IP` | 通用兜底 |

无需任何额外配置，直连和套 CDN 两种场景均可自动正确处理。

## 响应头说明

| 响应头 | 说明 |
|--------|------|
| `X-Proxied-By: CF-Worker-NextDNS` | 标识请求经过本 Worker 代理 |
| `X-Fallback: primary-timeout` | 主上游超时，已切换备用 |
| `X-Fallback: primary-error` | 主上游报错，已切换备用 |

## 常见问题

**Q：不设置 `BASE_PATH` 安全吗？**

默认路径 `/dns-query` 是标准 DoH 路径，任何人都能猜到。建议设置一个随机字符串作为自定义路径，如 `dns-a8f3kz2q`，起到隐藏端点的作用。

**Q：`NEXTDNS_ID` 在哪里找？**

登录 [NextDNS 控制台](https://my.nextdns.io)，进入你的配置，在 **Setup** 页面可以看到你的 DoH 地址，其中最后一段即为你的 ID，如 `https://dns.nextdns.io/a1b2c3` 中的 `a1b2c3`。

**Q：如何配置多个 NextDNS ID 分摊额度？**

在 `NEXTDNS_ID` 环境变量中用逗号分隔多个 ID，如 `a1b2c3,d4e5f6`。每次请求会随机选择一个 ID，两个 ID 各占 50% 请求量，以此类推。

**Q：备用 DoH 可以填哪些？**

任何标准 DoH 地址均可，例如：

- Cloudflare：`https://cloudflare-dns.com/dns-query`
- Quad9：`https://dns.quad9.net/dns-query`
- AdGuard：`https://dns.adguard.com/dns-query`

所有支持 ECS 的备用上游都会自动收到 ECS 注入，无需额外配置。

**Q：Worker 免费套餐够用吗？**

Cloudflare Workers 免费套餐每天有 10 万次请求额度，个人使用完全够用。

**Q：可以部署到 Cloudflare Pages 吗？**

可以。将文件放在 `functions/[[path]].js`，代码无需任何修改，同一份代码同时兼容 Worker 和 Pages Functions 两种部署方式。

## License

MIT

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/QSDR2s1d/NextDNS-Cloudflare-Worker)
