/* 本地验证 jsos-cors-proxy（双模式：直通 catch-all 形态 + Vercel rewrite 形态模拟） */
import http from 'node:http';
import handler from './api/proxy.js';

const PORT_A = 3986; // 直通形态：req.url 原样（catch-all 部署）
const PORT_B = 3987; // rewrite 形态：模拟 vercel.json rewrites /(.*) → /api/proxy?vercel_path=$1

const wrap = (mode) => async (req, res) => {
  if (mode === 'rewrite') {
    const u = new URL(req.url, 'http://local');
    const sp = new URLSearchParams(u.searchParams);
    sp.set('vercel_path', u.pathname.slice(1)); // 模拟 Vercel $1：不含开头斜杠
    req.url = '/api/proxy?' + sp.toString();
    req.query = Object.fromEntries(sp);
  }
  await handler(req, res);
};

const serverA = http.createServer(wrap('direct'));
const serverB = http.createServer(wrap('rewrite'));
await new Promise((r) => serverA.listen(PORT_A, r));
await new Promise((r) => serverB.listen(PORT_B, r));

const KEY = 'hello-world';
let pass = 0;
const results = [];
const check = (name, cond, extra = '') => {
  results.push(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`);
  if (cond) pass++;
};

/* 直通形态：核心三项 */
{
  const BASE = `http://localhost:${PORT_A}`;
  let r = await fetch(BASE + '/');
  let j = await r.json().catch(() => null);
  check('直通: 健康检查', r.status === 200 && j?.ok === true);

  r = await fetch(BASE + '/https://music.163.com/api/search/get?s=' + encodeURIComponent('晴天') + '&type=1&limit=1', {
    headers: { 'x-cors-proxy-key': KEY, Referer: 'https://music.163.com/' },
  });
  j = await r.json().catch(() => null);
  check('直通: GET https 目标透传', r.status === 200 && j?.result?.songs?.length > 0, j?.result?.songs?.[0]?.name || '');

  r = await fetch(BASE + '/http://8.129.83.45:9001/', { headers: { 'x-cors-proxy-key': KEY } });
  check('直通: 裸 IP 目标放行', r.status === 200, `status=${r.status}`);

  // encoded 形态（应用绕开双斜杠 308 的部署形态）
  r = await fetch(BASE + '/' + encodeURIComponent('https://music.163.com/api/search/get?s=' + encodeURIComponent('晴天') + '&type=1&limit=1'), {
    headers: { 'x-cors-proxy-key': KEY, Referer: 'https://music.163.com/' },
  });
  j = await r.json().catch(() => null);
  check('直通: encoded 路径透传', r.status === 200 && j?.result?.songs?.length > 0, j?.result?.songs?.[0]?.name || '');

  // query key 形态（无自定义头 → 不触发 preflight）
  r = await fetch(BASE + '/' + encodeURIComponent('https://music.163.com/api/search/get?s=' + encodeURIComponent('晴天') + '&type=1&limit=1') + '?x-cors-proxy-key=' + KEY, {
    headers: { Referer: 'https://music.163.com/' },
  });
  j = await r.json().catch(() => null);
  check('直通: query key 简单请求（无 preflight）', r.status === 200 && j?.result?.songs?.length > 0, j?.result?.songs?.[0]?.name || '');
}

/* rewrite 形态：全部断言（线上真实形态） */
{
  const BASE = `http://localhost:${PORT_B}`;
  let r = await fetch(BASE + '/');
  let j = await r.json().catch(() => null);
  check('rewrite: 健康检查', r.status === 200 && j?.ok === true, JSON.stringify(j)?.slice(0, 60));

  r = await fetch(BASE + '/whatever-no-key');
  check('rewrite: 缺 key → 401', r.status === 401);

  r = await fetch(BASE + '/https://music.163.com/api/search/get?s=' + encodeURIComponent('晴天') + '&type=1&limit=2', {
    headers: { 'x-cors-proxy-key': KEY, Referer: 'https://music.163.com/' },
  });
  j = await r.json().catch(() => null);
  check('rewrite: GET https 目标透传（query 重组）', r.status === 200 && j?.result?.songs?.length > 0,
    j?.result?.songs?.[0]?.name || `status=${r.status}`);

  r = await fetch(BASE + '/https://httpbin.org/status/404', { headers: { 'x-cors-proxy-key': KEY } });
  check('rewrite: 404 透传', r.status === 404, `status=${r.status}`);

  r = await fetch(BASE + '/https://music.163.com/api/cloudsearch/pc', {
    method: 'POST',
    headers: { 'x-cors-proxy-key': KEY, 'Content-Type': 'application/x-www-form-urlencoded', Referer: 'https://music.163.com/' },
    body: new URLSearchParams({ s: '晴天', type: '1', limit: '1', offset: '0' }),
  });
  j = await r.json().catch(() => null);
  check('rewrite: POST 透传', r.status === 200 && j?.result?.songs?.length > 0, j?.result?.songs?.[0]?.name || '');

  r = await fetch(BASE + '/http://8.129.83.45:9001/', { headers: { 'x-cors-proxy-key': KEY } });
  check('rewrite: 裸 IP 目标放行', r.status === 200, `status=${r.status}`);

  r = await fetch(BASE + '/http://127.0.0.1:80/', { headers: { 'x-cors-proxy-key': KEY } });
  check('rewrite: 私网目标 → 403', r.status === 403, `status=${r.status}`);

  r = await fetch(BASE + '/https://httpbin.org/range/100', {
    headers: { 'x-cors-proxy-key': KEY, Range: 'bytes=0-9' },
  });
  const buf = await r.arrayBuffer();
  check('rewrite: Range 透传（206）', r.status === 206 && buf.byteLength === 10, `status=${r.status} bytes=${buf.byteLength}`);
}

console.log(results.join('\n'));
console.log(`\n${pass}/${results.length} passed`);
serverA.close();
serverB.close();
process.exit(pass === results.length ? 0 : 1);
