# jsos-cors-proxy — JSOS 系统 CORS 代理（自部署版）

官方 `cors-proxy.jsos.dev` 的**协议兼容**自部署版，部署在 Vercel（绑定自定义域名后自带 HTTPS）。
官方服务失效或需要访问裸 IP 目标时，在 JSOS 设置里把代理地址换成自己的即可，**所有应用零改动切换**。

零依赖，单文件函数（`api/[[...path]].js`），流式透传，支持音频 Range 与 SSE。

## 协议（与官方完全一致）

```
ANY {本服务}/{完整目标URL}          目标 URL 裸拼在路径后，其 query 归目标
头: x-cors-proxy-key: {key}        缺失或错误 → 401
响应: Access-Control-Allow-Origin: * 等 CORS 头；目标状态码原样透传
```

```bash
# 示例
curl -H "x-cors-proxy-key: hello-world" \
  "https://<你的域名>/https://music.163.com/api/search/get?s=%E6%99%B4%E5%A4%A9&type=1&limit=2"
```

## 相比官方的两个增强

| 行为 | 官方 cors-proxy.jsos.dev | 本服务 |
|------|-------------------------|--------|
| https 域名目标 | ✅ | ✅ |
| 状态码/Range/Referer 透传 | ✅ | ✅ |
| **http 裸 IP 目标** | ❌ Cloudflare error 1003 | ✅ 放行（容器内直达自部署服务，如 99 起始页 9001） |
| **私网/回环目标** | — | ❌ 默认 403（防 SSRF），`ALLOW_PRIVATE_IP=true` 可关 |
| POST/SSE/流式 | 未验证 | ✅ 支持 |

## 部署步骤（GitHub → Vercel → 子域名）

1. **推到 GitHub**：
   ```bash
   cd jsos-cors-proxy
   git init && git add -A && git commit -m "feat: jsos-cors-proxy 初始化"
   gh repo create jsos-cors-proxy --public --source=. --push   # 或手动建仓库后 push
   ```

2. **Vercel 导入**：<https://vercel.com/new> → 选择 jsos-cors-proxy 仓库 → Framework Preset 选 **Other** → Deploy（环境变量可选，默认值即工作）

3. **绑定子域名**（主域保留 GitHub Pages 博客）：
   - Vercel 项目 → Settings → Domains → Add：`proxy.xn--4gqta1h0zg9yuu7a.fun`
   - 域名 DNS 加一条 CNAME：
     | 类型 | 主机记录 | 记录值 |
     |------|---------|--------|
     | CNAME | proxy | cname.vercel-dns.com |
   - 等 Vercel 自动签发 SSL（通常几分钟）

4. **验证**：
   ```bash
   curl "https://proxy.xn--4gqta1h0zg9yuu7a.fun/"
   # 期望: {"ok":true,"service":"jsos-cors-proxy",...}

   curl -H "x-cors-proxy-key: hello-world" \
     "https://proxy.xn--4gqta1h0zg9yuu7a.fun/http://8.129.83.45:9001/"
   # 期望: 200（裸 IP 目标，官方代理做不到的）

   curl -H "x-cors-proxy-key: hello-world" \
     "https://proxy.xn--4gqta1h0zg9yuu7a.fun/https://music.163.com/api/search/get?s=test&type=1&limit=1"
   # 期望: 200 + JSON
   ```

## 切换 JSOS 全局代理（官方失效 / 需要裸 IP 时）

**JSOS 设置 → CORS 代理设置**：

| 配置项 | 值 |
|--------|-----|
| 代理地址 | `https://proxy.xn--4gqta1h0zg9yuu7a.fun` |
| Key | `hello-world`（保持默认即可） |

保存后 JSOS 会把 `PROXY_URL` / `PROXY_KEY` 注入所有应用容器，music / daily-brief / random-box 等应用**无需任何改动**即切换到自建代理。

## 环境变量（Vercel 项目 Settings → Environment Variables，均可选）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ACCESS_KEY` | `hello-world` | 代理鉴权 key（`x-cors-proxy-key` 头），与 JSOS 默认配置对齐 |
| `ALLOW_PRIVATE_IP` | `false` | 是否允许私网/回环目标（保持默认，防 SSRF） |

## 区域与额度

- `vercel.json` 固定函数区域 `hkg1`（香港，大陆访问延迟低，到阿里云杭州快）
- Hobby 免费额度：音频大流量不在本代理走（music 的音频代理在应用容器内经本服务按需 Range 拉取），日常 JSON 转发流量极小
- 函数超时 60s（`maxDuration`）

## 本地开发 / 测试

```bash
node test-local.mjs   # 11 项断言：鉴权/透传/状态码/CORS/裸 IP/私网防护/Range
```
