# NextDNS DoH Proxy - 统一单文件版本

## 核心特性

**一个文件，三个平台** - `universal.js` 自动检测运行环境，无需手动配置

### 平台自动检测

```javascript
// 检测逻辑：
// - 有 Deno.env → Netlify Edge Functions
// - 有 process.env → Vercel Edge Functions
// - 默认 → Cloudflare Workers/Pages
```

## 环境变量配置

### 通用配置（所有平台）

| 变量 | 说明 | 默认值 | 必填 |
|------|------|--------|------|
| `NEXTDNS_ID` | NextDNS 配置 ID，多个用逗号分隔 | - | ✅ |
| `FALLBACK_URL` | 备用 DoH 服务器 | `https://dns.google/dns-query` | ❌ |
| `TIMEOUT_MS` | 主上游超时时间（毫秒） | `2500` | ❌ |

### 平台特定配置

**Cloudflare Workers/Pages**
- `BASE_PATH` - 路径前缀（默认：`/dns-query`）

**Vercel/Netlify Edge Functions**
- `MOUNT_PATH` - 挂载路径（默认：`/youimark`）

## 部署指南

### Cloudflare Workers

```bash
# 1. 配置 wrangler.toml（NEXTDNS_ID 建议在 Dashboard 中配置，避免暴露在代码仓库）
cat > wrangler.toml << EOF
name = "nextdns-proxy"
main = "_worker.js"
compatibility_date = "2026-04-01"

[vars]
BASE_PATH = "/dns-query"
EOF

# 2. 在 Cloudflare Dashboard 配置环境变量
#    Workers > nextdns-proxy > Settings > Variables > Add variable
#    NEXTDNS_ID = your_id_here

# 3. 部署
wrangler deploy
```

### Cloudflare Pages Functions

```bash
# 将 _worker.js 和 universal.js 放在 functions/ 目录
mkdir -p functions
cp _worker.js universal.js functions/

# 在 Pages 控制台配置环境变量
# NEXTDNS_ID = your_id_here
```

### Vercel

```bash
# 1. 确保项目结构正确
# api/youimark.js 已经配置好，会自动导入 universal.js

# 2. 配置环境变量
vercel env add NEXTDNS_ID

# 3. 部署
vercel deploy --prod
```

### Netlify

```bash
# 1. 确保项目结构正确
# netlify/edge-functions/youimark.js 已经配置好，会自动导入 universal.js

# 2. 配置环境变量（在 Netlify 控制台或 CLI）
netlify env:set NEXTDNS_ID your_id_here

# 3. 部署
netlify deploy --prod
```

## 使用示例

### GET 请求（标准 DoH）

```bash
# Cloudflare
curl "https://your-worker.workers.dev/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

# Vercel/Netlify
curl "https://your-domain.com/youimark?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
```

### POST 请求

```bash
curl -X POST https://your-domain.com/dns-query \
  -H "Content-Type: application/dns-message" \
  --data-binary @dns-query.bin
```

### 带设备 ID

```bash
# Cloudflare
curl "https://your-worker.workers.dev/dns-query/my-iphone?dns=..."

# Vercel（通过 rewrite）
curl "https://your-domain.com/youimark/my-iphone?dns=..."

# Netlify
curl "https://your-domain.com/youimark/my-iphone?dns=..."
```

## 技术细节

### 自动平台检测

```javascript
const detectPlatform = () => {
  if (typeof Deno !== 'undefined' && Deno.env) return 'netlify';
  if (typeof process !== 'undefined' && process.env) return 'vercel';
  return 'cloudflare';
};
```

### 统一环境变量读取

```javascript
const getEnv = (key, env) => {
  const platform = detectPlatform();
  if (platform === 'netlify') return Deno.env.get(key);
  if (platform === 'vercel') return process.env[key];
  return env?.[key]; // Cloudflare
};
```

### 平台特定 IP 提取

```javascript
const headers = {
  cloudflare: ['CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP'],
  vercel: ['X-Vercel-Forwarded-For', 'X-Forwarded-For', 'X-Real-IP'],
  netlify: ['X-Nf-Client-Connection-Ip', 'X-Forwarded-For', 'X-Real-IP'],
};
```

## 核心功能

✅ **DNS over HTTPS (DoH)** - RFC 8484 标准协议
✅ **ECS 注入** - EDNS Client Subnet (RFC 7871)
✅ **IPv4/IPv6 支持** - 完整的 IP 解析和验证
✅ **故障转移** - 主上游失败自动切换备用
✅ **超时控制** - 防止请求挂起
✅ **安全防护** - 输入验证、路径遍历防护、大小限制
✅ **CORS 支持** - 跨域请求友好
✅ **负载均衡** - 多个 NextDNS ID 随机选择

## 安全特性

- **输入验证** - DNS 消息格式、Base64URL 编码检查
- **路径遍历防护** - 过滤 `..` 和隐藏文件
- **请求大小限制** - 64KB 上限
- **响应大小限制** - 64KB 上限，防止恶意上游攻击
- **超时保护** - 主上游 2.5s，备用 1.5s
- **错误隔离** - 统一错误处理，不泄露内部信息
- **公网 IP 检测** - 仅对公网 IP 注入 ECS

## 维护优势

1. **单文件维护** - 只需维护 `universal.js`
2. **自动适配** - 无需手动指定平台
3. **向后兼容** - 保持原有文件名和接口
4. **易于测试** - 核心逻辑集中在一个文件
5. **代码复用** - 消除重复代码

## 故障排查

### 检查平台检测

在 `universal.js` 开头添加日志：

```javascript
console.log('Detected platform:', detectPlatform());
```

### 检查环境变量

```javascript
console.log('NEXTDNS_ID:', getEnv('NEXTDNS_ID', env));
```

### 检查客户端 IP

```javascript
console.log('Client IP:', clientIP);
```

## 性能优化

- **随机负载均衡** - 多个 NextDNS ID 分散请求
- **快速故障转移** - 超时后立即切换备用
- **最小化解析** - 仅在需要时解析 DNS 消息
- **ECS 缓存** - 避免重复注入
