/**
 * /api/oss-sign —— 为 JSOS 云同步签发阿里云 OSS 预签名 URL
 * ---------------------------------------------------------------
 * 为什么需要它：浏览器端拿不到 AK/SK（会随应用包泄露），所以签名必须放在可信服务端。
 * 本接口只做一件事：把「objectKey + 操作」换成一条短时有效的预签名 URL；
 * 客户端拿到后**直连 OSS** 传输数据 —— 数据不经过本函数，因此完全不受
 * Vercel 4.5 MB 请求体上限的约束。这正是绕开云同步体积瓶颈的关键一跳。
 *
 * 用法：
 *   GET /oss-sign?key=jsos-sync/<同步码>.json&op=put
 *   Header: x-cors-proxy-key: <ACCESS_KEY>      （也接受同名 query 参数，与 proxy 一致）
 *
 * ⚠️ 对外路径是 **`/oss-sign`**（不是 /api/oss-sign）：vercel.json 的 catch-all rewrite
 *    会把一切路径都重写进 /api/proxy，所以这里在 rewrites 里补了一条更靠前的
 *    { "source": "/oss-sign", "destination": "/api/oss-sign" } 让它命中本文件。
 *    这样无论 Vercel 是「文件系统优先」还是「rewrites 优先」，本接口都能被正确路由。
 *
 * 返回：
 *   { ok:true, method:"PUT", url:"https://...", key:"...", expiresIn:600 }
 *
 * 零依赖：纯 node:crypto 实现 OSS V1(URL) 签名。
 *   stringToSign = VERB \n Content-MD5 \n Content-Type \n Expires \n CanonicalizedOSSHeaders + CanonicalizedResource
 *   URL 签名时 Content-MD5 与 Content-Type 必须留空，故中间两个 \n 之间为空字符串。
 *   ⚠️ 客户端 PUT 时不要设置 Content-Type，否则会 SignatureDoesNotMatch。
 *
 * 环境变量（Vercel 项目 Settings → Environment Variables）：
 *   OSS_AK / OSS_SK / OSS_BUCKET   必填
 *   OSS_REGION     默认 oss-cn-shenzhen
 *   ACCESS_KEY     默认 hello-world（与 cors 代理共用）
 *   OSS_SIGN_EXPIRES 默认 600（秒）
 *   OSS_ALLOW_PREFIX 默认 jsos-sync/
 */
import crypto from 'node:crypto';

const ACCESS_KEY = process.env.ACCESS_KEY || 'hello-world';
const OSS_AK = process.env.OSS_AK || '';
const OSS_SK = process.env.OSS_SK || '';
const OSS_BUCKET = process.env.OSS_BUCKET || '';
const OSS_REGION = process.env.OSS_REGION || 'oss-cn-shenzhen';
const EXPIRES_SEC = Number(process.env.OSS_SIGN_EXPIRES || 600);
/** 允许签名的 key 前缀白名单 —— 防止本接口被用来签发任意对象的访问权 */
const ALLOW_PREFIX = process.env.OSS_ALLOW_PREFIX || 'jsos-sync/';

const OPS = { put: 'PUT', get: 'GET', head: 'HEAD', delete: 'DELETE' };

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-expose-headers': '*',
  'access-control-max-age': '86400',
};

function presign(method, key) {
  const expires = Math.floor(Date.now() / 1000) + EXPIRES_SEC;
  const canonicalResource = `/${OSS_BUCKET}/${key}`;
  const stringToSign = `${method}\n\n\n${expires}\n${canonicalResource}`;
  const signature = crypto.createHmac('sha1', OSS_SK).update(stringToSign, 'utf8').digest('base64');
  const qs = new URLSearchParams({
    OSSAccessKeyId: OSS_AK,
    Expires: String(expires),
    Signature: signature,
  });
  const url = `https://${OSS_BUCKET}.${OSS_REGION}.aliyuncs.com/${key}?${qs.toString()}`;
  return { url, expires };
}

function keyProblem(key) {
  if (!key) return 'key 不能为空';
  if (key.length > 512) return 'key 过长';
  if (!key.startsWith(ALLOW_PREFIX)) return `key 必须以 ${ALLOW_PREFIX} 开头`;
  if (key.includes('..') || key.includes('//') || key.includes('\\')) return 'key 含非法路径片段';
  return null;
}

export default function handler(req, res) {
  const send = (status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...CORS });
    res.end(JSON.stringify(obj));
  };

  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    return res.end();
  }
  if (req.method !== 'GET') {
    return send(405, { error: 405, message: 'Method Not Allowed，用法见 2.0 版说明：GET /api/oss-sign?key=&op=' });
  }

  if (!OSS_AK || !OSS_SK || !OSS_BUCKET) {
    return send(500, { error: 500, message: '服务端未配置 OSS_AK / OSS_SK / OSS_BUCKET' });
  }

  const q = req.query || {};
  const presentedKey = req.headers['x-cors-proxy-key'] || q['x-cors-proxy-key'] || '';
  if (presentedKey !== ACCESS_KEY) {
    return send(401, { error: 401, message: 'Invalid or missing x-cors-proxy-key' });
  }

  const key = String(q.key || '');
  const op = String(q.op || 'put').toLowerCase();
  const method = OPS[op];
  if (!method) {
    return send(400, { error: 400, message: 'op 必须是 put / get / head / delete 之一' });
  }
  const bad = keyProblem(key);
  if (bad) {
    return send(400, { error: 400, message: bad });
  }

  const { url, expires } = presign(method, key);
  return send(200, {
    ok: true,
    method,
    url,
    key,
    bucket: OSS_BUCKET,
    region: OSS_REGION,
    expiresIn: EXPIRES_SEC,
    expiresAt: expires,
  });
}
