/**
 * jsos-cors-proxy — JSOS 系统 CORS 代理的自部署版（协议兼容官方 cors-proxy.jsos.dev）
 * ---------------------------------------------------------------
 * 协议（与官方一致，见 jsos-apps/AGENTS.md §7.5）：
 *   ANY {本服务}/{完整目标URL}          目标 URL 裸拼在路径后，其 query 归目标
 *   头: x-cors-proxy-key: {key}        缺失或错误 → 401
 *   响应: Access-Control-Allow-Origin: * 等 CORS 头，目标状态码原样透传
 *
 * 相比官方的两个增强：
 *   1. 支持 http 裸 IP 目标（官方被 Cloudflare error 1003 拒绝）——
 *      用于容器内直达自部署服务（如 99 起始页 http://8.129.83.45:9001）
 *   2. 私网/回环目标默认拒绝（防 SSRF），ALLOW_PRIVATE_IP=true 可关闭
 *
 * 流式透传：音频（Range）、SSE 均支持；响应自动补 CORS 头。
 * 零依赖，Vercel Node runtime。
 */

const ACCESS_KEY = process.env.ACCESS_KEY || 'hello-world';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_IP === 'true';

/** 代理保留的 query 参数：不透传给目标站，由本服务消费。
 *  x-cors-proxy-key   鉴权（头形态的等价物，供"零自定义头"请求使用）
 *  x-upstream-referer 转发时注入 Referer —— 浏览器/WebContainer 的 fetch 禁止
 *                     设置 Referer/User-Agent（会被静默丢弃），防盗链目标
 *                     （如 B 站 CDN）缺 Referer 一律 403，只能经此透传
 *  x-upstream-ua      转发时注入 User-Agent（同理） */
const RESERVED_PARAMS = new Set(['x-cors-proxy-key', 'x-upstream-referer', 'x-upstream-ua']);
const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

/** 从目标 URL 上剥离保留参数，返回 { 参数名: 值 } */
function extractReservedParams(u) {
  const reserved = {};
  for (const k of RESERVED_PARAMS) {
    const v = u.searchParams.get(k);
    if (v !== null) {
      reserved[k] = v;
      u.searchParams.delete(k);
    }
  }
  return reserved;
}

const REQ_HOP_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
  'x-cors-proxy-key',
  'x-vercel-id', 'x-vercel-cache', 'x-vercel-deployment-url', 'x-vercel-forwarded-for',
  'x-vercel-internal-ingress-bucket', 'x-vercel-ip-city', 'x-vercel-ip-continent',
  'x-vercel-ip-country', 'x-vercel-ip-country-region', 'x-vercel-ip-latitude',
  'x-vercel-ip-longitude', 'x-vercel-ip-timezone', 'x-vercel-proxy', 'x-vercel-forward',
  'x-real-ip', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
  'x-forwarded-proto', 'x-forwarded-scheme', 'forwarded', 'cdn-loop',
]);

const RESP_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'content-encoding',
  'strict-transport-security', 'server', 'via', 'alt-svc', 'x-vercel-cache', 'x-vercel-id',
]);

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': '*',
  'access-control-allow-methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
  'access-control-expose-headers': '*',
  'access-control-max-age': '86400',
};

/* ---------------- 私网/回环防护（防 SSRF） ---------------- */

function isPrivateHost(hostname) {
  let host = String(hostname || '').toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host === '::' || /^fe80(:|$)/.test(host) || /^f[cd][0-9a-f]{2}:/.test(host)) return true;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if ([a, b, Number(m[3]), Number(m[4])].some((x) => x > 255)) return false;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

/* ---------------- 目标 URL 解析 ---------------- */

/**
 * 形态 A：从 req.url 还原目标（catch-all / 直通部署形态）。
 * 官方协议是裸拼：/{https://target.com/path?query} —— req.url 的路径部分
 * 是目标 URL 主体，query 归目标。兼容三种变形：
 *   a. 目标被 encodeURIComponent 过（%3A%2F 开头，encoded 形态——应用为绕开
 *      Vercel 对双斜杠的 308 规范化而主动编码，全路径无裸 ?）→ 解码还原
 *   b. 中间层把 // 折叠成 /（https:/target.com）→ 修复协议斜杠
 *   c. 代理层追加的 query（x-cors-proxy-key 鉴权参数）→ 从目标里剥离
 */
function resolveTargetFromUrl(reqUrl) {
  let raw = reqUrl || '';
  if (raw.startsWith('/')) raw = raw.slice(1);
  if (!raw) return null;
  const qIdx = raw.indexOf('?');
  let pathPart = qIdx === -1 ? raw : raw.slice(0, qIdx);
  let queryPart = qIdx === -1 ? '' : raw.slice(qIdx + 1);
  if (!pathPart) return null;

  const encoded = /^https?%3A/i.test(pathPart);
  if (encoded) {
    // encoded 形态：目标整体（含其自身 query）被编码在路径里
    try { pathPart = decodeURIComponent(pathPart); } catch { /* 保持原样 */ }
    const sp = new URLSearchParams(queryPart);
    sp.delete('x-cors-proxy-key');
    const extra = sp.toString();
    if (extra) pathPart += (pathPart.includes('?') ? '&' : '?') + extra;
  } else if (queryPart) {
    // 裸拼形态：target 自身的 query 原样归属目标
    pathPart += '?' + queryPart;
  }
  // 修复被折叠的协议斜杠：https:/x → https://x（首处）
  pathPart = pathPart.replace(/^(https?:)\/+/i, '$1//');
  if (!/^https?:\/\//i.test(pathPart)) return null;
  try {
    const u = new URL(pathPart);
    return { url: u, reserved: extractReservedParams(u) };
  } catch {
    return null;
  }
}

/**
 * 形态 B：从 rewrite 注入的 vercel_path query 还原目标。
 * vercel.json: { "source": "/(.*)", "destination": "/api/proxy?vercel_path=$1" }
 * Vercel 会把目标 URL 自身的 query 追加到顶层参数，重组时拼回去。
 */
function resolveTargetFromQuery(req) {
  const q = req.query || {};
  const vp = q.vercel_path;
  if (vp === undefined) return null;
  let raw = Array.isArray(vp) ? vp.join('/') : String(vp);
  try { raw = decodeURIComponent(raw); } catch { /* 保持原样 */ }
  raw = String(raw).replace(/^(https?:)\/+/i, '$1//');
  if (!raw || !/^https?:\/\//i.test(raw)) return null;

  // 顶层其余参数 = 目标自己的 query（rewrite 追加），拼回目标 URL；保留参数剥离
  const extra = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (k === 'vercel_path' || RESERVED_PARAMS.has(k)) continue;
    for (const item of Array.isArray(v) ? v : [v]) extra.append(k, item);
  }
  const qs = extra.toString();
  if (qs) raw += (raw.includes('?') ? '&' : '?') + qs;

  try {
    const u = new URL(raw);
    return { url: u, reserved: extractReservedParams(u) };
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  const sendJson = (status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...CORS_HEADERS });
    res.end(JSON.stringify(obj));
  };

  // CORS 预检（浏览器直连本代理时需要；服务端 fetch 不会触发）
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  // 健康检查（直通形态的根路径 + rewrite 形态的 / 或空 vercel_path）
  const vpRaw = req.query ? String(req.query.vercel_path ?? '') : null;
  const rewrittenEmpty = vpRaw !== null && (vpRaw === '' || vpRaw === '/');
  if (req.url === '/' || req.url === '' || req.url.startsWith('/favicon.ico') || rewrittenEmpty) {
    return sendJson(200, { ok: true, service: 'jsos-cors-proxy', usage: 'GET /{target-url} with x-cors-proxy-key header' });
  }

  // 鉴权（对齐官方：x-cors-proxy-key 缺失或错误 → 401）
  // 支持两种携带方式：请求头（官方协议）/ URL query（应用发"无自定义头"的简单请求，
  // 避免 WebContainer 容器内 Node fetch 的 preflight 被 Vercel 边缘 308 拦截）
  const queryKey = (() => {
    try { return new URL(req.url, 'http://local').searchParams.get('x-cors-proxy-key'); }
    catch { return null; }
  })();
  const presentedKey = req.headers['x-cors-proxy-key'] || queryKey || '';
  if (presentedKey !== ACCESS_KEY) {
    return sendJson(401, { error: 401, message: 'Invalid or missing x-cors-proxy-key' });
  }

  // 解析目标：形态 A（req.url 裸拼）→ 形态 B（rewrite 的 vercel_path）
  const resolved = resolveTargetFromUrl(req.url) || resolveTargetFromQuery(req);
  if (!resolved) {
    return sendJson(400, { error: 400, service: 'jsos-cors-proxy', message: '目标 URL 无效。用法: GET /{完整目标URL}，头 x-cors-proxy-key' });
  }
  const target = resolved.url;
  const reserved = resolved.reserved || {};
  if (!ALLOW_PRIVATE && isPrivateHost(target.hostname)) {
    return sendJson(403, { error: 403, message: '不允许代理私网/回环地址' });
  }

  // 组装上游请求头（透传常规头，剥离逐跳/网关注入头）
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (!REQ_HOP_HEADERS.has(key.toLowerCase())) headers[key] = value;
  }
  // 目标主机与协议归属上游，不能把本服务的 Host 带过去
  delete headers.host;

  // 保留参数消费：注入 Referer/UA（浏览器 fetch 发不出的头，防盗链目标必需）
  if (reserved['x-upstream-referer']) headers['referer'] = reserved['x-upstream-referer'];
  if (reserved['x-upstream-ua']) headers['user-agent'] = reserved['x-upstream-ua'];
  else if (!headers['user-agent']) headers['user-agent'] = DEFAULT_UA;

  try {
    let body;
    if (!['GET', 'HEAD'].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      body = Buffer.concat(chunks);
      if (body.length === 0) body = undefined;
    }

    const upstream = await fetch(target.href, {
      method: req.method,
      headers,
      body,
      redirect: 'follow',
      signal: AbortSignal.timeout(55000),
    });

    // 响应头：目标头原样（去逐跳头/解压相关头）+ CORS 头，状态码透传
    const respHeaders = { ...CORS_HEADERS };
    upstream.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (!RESP_HOP_HEADERS.has(k) && !CORS_HEADERS[k]) respHeaders[key] = value;
    });

    res.writeHead(upstream.status, respHeaders);
    if (!upstream.body) return res.end();

    // 流式透传（Range 音频 / SSE / 大响应）
    const { Readable } = await import('node:stream');
    const stream = Readable.fromWeb(upstream.body);
    res.on('close', () => stream.destroy());
    stream.on('error', () => res.end());
    stream.pipe(res);
  } catch (err) {
    if (!res.headersSent) {
      sendJson(502, { error: 502, message: `上游请求失败: ${err?.name === 'TimeoutError' ? 'timeout' : (err?.message || err)}` });
    } else {
      res.end();
    }
  }
}
