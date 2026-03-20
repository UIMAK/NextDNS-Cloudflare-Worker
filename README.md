# NextDNS Cloudflare Worker 反代

**[English](https://github.com/QSDR2s1d/NextDNS-Cloudflare-Worker/blob/main/README.en.md) | 中文**

一个基于 Cloudflare Worker 的 NextDNS DoH 反向代理，支持自定义路径、备用上游、ECS 透传和超时自动切换。

## 功能特性

- 🔒 **隐藏路径鉴权**：自定义 DoH 路径，不知道路径的请求直接 404
- 🌍 **ECS 透传**：自动将客户端真实 IP 子网传递给上游，确保 DNS 解析结果地理位置准确
- 🔄 **自动 Fallback**：主上游超时或报错时自动切换备用 DoH
- ⏱️ **超时控制**：使用 `AbortController` 真正中止超时请求，避免资源浪费
- ⚙️ **全环境变量配置**：无需修改代码，所有参数通过环境变量控制

## 部署

### 1. 创建 Worker

登录 [Cloudflare Dashboard](https://dash.cloudflare.com)，进入 **Workers & Pages → Create application → Create Worker**，将 `worker.js` 的内容粘贴进去，保存并部署。

### 2. 配置环境变量

进入 Worker 的 **Settings → Variables**，添加以下环境变量：

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `NEXTDNS_ID` | ✅ | 无 | 你的 NextDNS 配置 ID，在 NextDNS 控制台 Setup 页面查看 |
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

## 工作原理

```
设备发出 DNS 请求
       ↓
Cloudflare Worker 接收请求
       ↓
提取客户端真实 IP（CF-Connecting-IP）
生成 /24（IPv4）或 /48（IPv6）子网掩码
       ↓
转发至 NextDNS（附带 ECS 子网参数 ?ci=）
       ↓
超时或报错？→ 自动切换备用 DoH
       ↓
返回 DNS 响应给设备
```

## ECS 说明

ECS（EDNS Client Subnet）让 DNS 服务器知道客户端大致位置，从而返回地理位置最优的 CDN 节点。

本 Worker 的处理方式：

- **NextDNS**：通过 `?ci=` 参数传递客户端 IP 子网（官方支持的方式）
- **Google DoH**（默认备用）：通过 `?edns_client_subnet=` 参数传递
- **其他备用**：不传递 ECS 参数，避免不兼容问题

为保护隐私，只传递 IP 子网而非完整 IP：

- IPv4：传递 `/24`，如 `1.2.3.0/24`
- IPv6：传递 `/48`，如 `2001:db8:1::/48`

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

**Q：备用 DoH 可以填哪些？**

任何标准 DoH 地址均可，例如：

- Cloudflare：`https://cloudflare-dns.com/dns-query`
- Quad9：`https://dns.quad9.net/dns-query`
- AdGuard：`https://dns.adguard.com/dns-query`

注意：只有备用为 Google DoH 时才会自动透传 ECS 参数，其他服务商不传递。

**Q：Worker 免费套餐够用吗？**

Cloudflare Workers 免费套餐每天有 10 万次请求额度，个人使用完全够用。

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/QSDR2s1d/NextDNS-Cloudflare-Worker)
