/* 本地验证 jsos-cors-proxy（模拟 Vercel Node runtime 调用 handler） */
import http from 'node:http';
import handler from './api/[[...path]].js';

const PORT = 3988;
const KEY = 'hello-world';
const server = http.createServer(async (req, res) => {
  await handler(req, res);
});
await new Promise((r) => server.listen(PORT, r));
const BASE = `http://localhost:${PORT}`;

let pass = 0, skip = 0;
const check = (name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
  if (cond) pass++;
};
const skipTest = (name, why) => { console.log(`SKIP  ${name}  (${why})`); skip++; };

/* 1. 健康检查 */
{
  const r = await fetch(BASE + '/');
  const j = await r.json();
  check('健康检查', r.status === 200 && j.ok === true);
}

/* 2/3. 鉴权 */
{
  const r = await fetch(BASE + '/https://example.com/');
  check('缺 x-cors-proxy-key → 401', r.status === 401);
  const r2 = await fetch(BASE + '/https://example.com/', { headers: { 'x-cors-proxy-key': 'wrong' } });
  check('错 x-cors-proxy-key → 401', r2.status === 401);
}

/* 4. GET https 目标透传 + CORS 头 */
{
  const r = await fetch(BASE + '/https://music.163.com/api/search/get?s=' + encodeURIComponent('晴天') + '&type=1&limit=2', {
    headers: { 'x-cors-proxy-key': KEY, Referer: 'https://music.163.com/' },
  });
  const j = await r.json().catch(() => null);
  check('GET https 目标透传', r.status === 200 && j?.result?.songs?.length > 0,
    j?.result?.songs?.[0]?.name || '');
  check('响应带 Access-Control-Allow-Origin: *', (r.headers.get('access-control-allow-origin') || '') === '*');
}

/* 5. 状态码透传 */
{
  const r = await fetch(BASE + '/https://httpbin.org/status/404', {
    headers: { 'x-cors-proxy-key': KEY },
  });
  check('目标 404 → 代理 404', r.status === 404, `status=${r.status}`);
}

/* 6. POST 透传 */
{
  const r = await fetch(BASE + '/https://music.163.com/api/cloudsearch/pc', {
    method: 'POST',
    headers: { 'x-cors-proxy-key': KEY, 'Content-Type': 'application/x-www-form-urlencoded', Referer: 'https://music.163.com/' },
    body: new URLSearchParams({ s: '晴天', type: '1', limit: '1', offset: '0' }),
  });
  const j = await r.json().catch(() => null);
  check('POST 透传', r.status === 200 && j?.result?.songs?.length > 0, j?.result?.songs?.[0]?.name || `status=${r.status}`);
}

/* 7. 裸 IP 目标（自建增强：官方在此返回 error 1003） */
{
  const r = await fetch(BASE + '/http://8.129.83.45:9001/', { headers: { 'x-cors-proxy-key': KEY } });
  const ok = r.status === 200;
  check('裸 IP 目标放行（官方 1003 → 我们 200）', ok, `status=${r.status}`);
}

/* 8. 私网防护 */
{
  const r = await fetch(BASE + '/http://127.0.0.1:80/', { headers: { 'x-cors-proxy-key': KEY } });
  check('私网目标 → 403', r.status === 403, `status=${r.status}`);
}

/* 9. OPTIONS 预检 */
{
  const r = await fetch(BASE + '/https://example.com/', { method: 'OPTIONS' });
  check('OPTIONS 预检 → 204 + CORS', r.status === 204 && (r.headers.get('access-control-allow-origin') || '') === '*');
}

/* 10. Range 透传（流式） */
{
  try {
    const r = await fetch(BASE + '/https://httpbin.org/range/100', {
      headers: { 'x-cors-proxy-key': KEY, Range: 'bytes=0-9' },
    });
    const buf = await r.arrayBuffer();
    check('Range 透传（206 流式）', r.status === 206 && buf.byteLength === 10, `status=${r.status} bytes=${buf.byteLength}`);
  } catch {
    skipTest('Range 透传', 'httpbin.org 不可达');
  }
}

console.log(`\n${pass} passed, ${skip} skipped`);
server.close();
process.exit(0);
