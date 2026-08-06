// ============= 文本云盘 Worker（基于Cloudflare）=============
const DEFAULT_FRONTEND_URL = "https://d5s3g5.777777.qzz.io/";
const ADMIN_COOKIE_MAX_AGE = 3600; //默认1个小时，可按需修改
const KV_TTL = 60 * 60 * 24 * 7;
const CACHE_TTL = 60 * 60 * 24 * 365;
const MAX_HISTORY = 5; // 每个文件最多保留的历史版本数
let ADMIN_UUID = null;
let dbInitialized = false;

function uuidv4() {
  return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, (c) =>
    (
      c ^
      (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))
    ).toString(16),
  );
}
function isFolder(name) {
  return name.endsWith("/");
}
function getParentPath(path) {
  const p = path.split("/").filter(Boolean);
  p.pop();
  return p.length ? p.join("/") + "/" : "";
}
function getBaseName(path) {
  const p = path.split("/");
  return isFolder(path) ? p[p.length - 2] + "/" : p[p.length - 1];
}
function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function text(data, status = 200, headers = {}) {
  return new Response(data, {
    status,
    headers: {
      "Content-Type": "text/plain;charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      ...headers,
    },
  });
}
function sanitizePath(path) {
  if (!path) return "";
  if (typeof path !== "string") throw new Error("非法文件名");
  if (path.includes("..")) throw new Error("非法文件名");
  return path;
}

// ---------- 安全工具函数 ----------

// 恒定时间字符串比较，避免通过响应耗时推断出正确值
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const aBuf = enc.encode(a);
  const bBuf = enc.encode(b);
  // 长度不同也要跑一次固定长度的比较，减少长度提前泄露的时间差
  const len = Math.max(aBuf.length, bBuf.length, 32);
  let diff = aBuf.length ^ bBuf.length;
  for (let i = 0; i < len; i++) {
    const x = i < aBuf.length ? aBuf[i] : 0;
    const y = i < bBuf.length ? bBuf[i] : 0;
    diff |= x ^ y;
  }
  return diff === 0;
}

// LIKE 模式转义：防止用户输入中的 % _ \ 被当作通配符解释
function escapeLike(str) {
  return String(str)
    .replace(/\\/g, "\\\\")
    .replace(/%/g, "\\%")
    .replace(/_/g, "\\_");
}

function arrayBufferToBase64Url(buf) {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacSign(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return arrayBufferToBase64Url(sig);
}

function getSessionSecret(env) {
  // 建议单独设置 SESSION_SECRET；未设置时退化使用 ADMIN_UUID（仍优于直接把 UUID 当 cookie 明文使用）
  return env.SESSION_SECRET || env.ADMIN_UUID;
}

// 签发一个带过期时间、经 HMAC 签名的会话 token，而不是把主密钥直接下发给浏览器
async function createSessionToken(env) {
  const exp = Date.now() + ADMIN_COOKIE_MAX_AGE * 1000;
  const payload = `${exp}.${uuidv4()}`; // 加入随机数，避免同一时刻多次登录 token 完全一致
  const sig = await hmacSign(getSessionSecret(env), payload);
  return `${payload}.${sig}`;
}

// 校验会话 token：签名必须匹配，且未过期
async function verifySessionToken(env, token) {
  if (!token || typeof token !== "string") return false;
  const idx = token.lastIndexOf(".");
  if (idx === -1) return false;
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expectedSig = await hmacSign(getSessionSecret(env), payload);
  if (!timingSafeEqual(sig, expectedSig)) return false;
  const expStr = payload.split(".")[0];
  const exp = parseInt(expStr, 10);
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;
  return true;
}

// 可选的 Cloudflare Turnstile 人机验证
async function verifyTurnstile(env, token, ip) {
  if (env.TURNSTILE !== "true") return true; // 未开启则直接放行
  if (!env.TURNSTILE_SECRET_KEY) {
    // 开启了但没配 secret，出于安全考虑直接拒绝，而不是静默放行
    return false;
  }
  if (!token) return false;
  const formData = new FormData();
  formData.append("secret", env.TURNSTILE_SECRET_KEY);
  formData.append("response", token);
  if (ip) formData.append("remoteip", ip);
  try {
    const res = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: formData },
    );
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

async function initDB(env) {
  if (dbInitialized) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,is_folder INTEGER NOT NULL,content TEXT,token TEXT,share_expires_at INTEGER,created_at INTEGER DEFAULT(unixepoch()),updated_at INTEGER DEFAULT(unixepoch()));CREATE INDEX IF NOT EXISTS idx_path_prefix ON files(path);`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS file_history(id INTEGER PRIMARY KEY AUTOINCREMENT,path TEXT NOT NULL,content TEXT,saved_at INTEGER DEFAULT(unixepoch()));CREATE INDEX IF NOT EXISTS idx_history_path ON file_history(path);`,
  ).run();
  // 兼容旧版表结构：为已存在的 files 表补上分享过期时间列
  try {
    await env.DB.prepare(
      "ALTER TABLE files ADD COLUMN share_expires_at INTEGER",
    ).run();
  } catch (e) {
    // 列已存在时 D1 会报错，忽略即可
  }
  dbInitialized = true;
}
function getCacheKey(request, token, path) {
  const u = new URL(request.url);
  return new Request(
    `${u.origin}/__cache__/${token}_${encodeURIComponent(path)}`,
  );
}
async function getCFCache(request, token, path) {
  return caches.default.match(getCacheKey(request, token, path));
}
async function putCFCache(request, token, path, content) {
  return caches.default.put(
    getCacheKey(request, token, path),
    new Response(content, {
      headers: {
        "Content-Type": "text/plain;charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": `public,max-age=${CACHE_TTL}`,
      },
    }),
  );
}
async function purgeCFCache(request, token, path) {
  if (!token) return;
  return caches.default.delete(getCacheKey(request, token, path));
}
async function getKVKey(token, path) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(path),
  );
  const hex = Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
  return `share_${token}_${hex}`;
}
async function setShareCache(env, token, path, content, oldToken, expireAt) {
  if (!env.SHARE_KV || !token) return;
  let ttl = KV_TTL;
  if (expireAt) {
    const remain = expireAt - Math.floor(Date.now() / 1000);
    ttl = Math.max(1, Math.min(remain, KV_TTL));
  }
  const opts = KV_TTL > 0 ? { expirationTtl: ttl } : {};
  await env.SHARE_KV.put(
    await getKVKey(token, path),
    JSON.stringify({ token, content, expireAt: expireAt || 0 }),
    opts,
  );
  if (oldToken && oldToken !== token)
    await env.SHARE_KV.delete(await getKVKey(oldToken, path));
}
async function updateShareCache(env, token, path, content, expireAt) {
  if (!env.SHARE_KV || !token) return;
  let ttl = KV_TTL;
  if (expireAt) {
    const remain = expireAt - Math.floor(Date.now() / 1000);
    ttl = Math.max(1, Math.min(remain, KV_TTL));
  }
  await env.SHARE_KV.put(
    await getKVKey(token, path),
    JSON.stringify({ token, content, expireAt: expireAt || 0 }),
    KV_TTL > 0 ? { expirationTtl: ttl } : {},
  );
}
async function deleteShareCache(env, token, path) {
  if (env.SHARE_KV && token)
    await env.SHARE_KV.delete(await getKVKey(token, path));
}
async function getShareCache(env, token, path) {
  if (!env.SHARE_KV) return null;
  const raw = await env.SHARE_KV.get(await getKVKey(token, path));
  if (!raw) return null;
  try {
    const o = JSON.parse(raw);
    if (o.token !== token) return null;
    // 兼容旧版 KV 值（无 expireAt 字段）：视为长期有效
    return { content: o.content ?? "", expireAt: o.expireAt || 0 };
  } catch {
    return null;
  }
}
async function getFileList(env) {
  return (
    await env.DB.prepare(
      "SELECT path, is_folder FROM files ORDER BY path",
    ).all()
  ).results.map((r) => ({ name: r.path, isFolder: r.is_folder === 1 }));
}
async function getFileContent(env, filename) {
  if (isFolder(filename)) return "";
  return (
    (
      await env.DB.prepare("SELECT content FROM files WHERE path = ?")
        .bind(filename)
        .all()
    ).results[0]?.content || ""
  );
}

// 写入一条历史版本，并裁剪到最多 MAX_HISTORY 条
async function pushHistory(env, path, content) {
  await env.DB.prepare(
    "INSERT INTO file_history (path, content, saved_at) VALUES (?, ?, unixepoch())",
  )
    .bind(path, content)
    .run();
  await env.DB.prepare(
    `DELETE FROM file_history WHERE path = ? AND id NOT IN (
       SELECT id FROM file_history WHERE path = ? ORDER BY saved_at DESC, id DESC LIMIT ?
     )`,
  )
    .bind(path, path, MAX_HISTORY)
    .run();
}

async function saveFileContent(env, filename, content, token = null) {
  if (isFolder(filename)) return null;
  const row = await env.DB.prepare(
    "SELECT token, content, share_expires_at FROM files WHERE path = ?",
  )
    .bind(filename)
    .all();
  if (!row.results.length) throw new Error("文件不存在，请先创建文件");
  const oldContent = row.results[0].content || "";
  if (token === null) token = row.results[0].token || null;
  const res = await env.DB.prepare(
    "UPDATE files SET content = ?, updated_at = unixepoch() WHERE path = ? AND is_folder = 0",
  )
    .bind(content, filename)
    .run();
  if (res.changes === 0) throw new Error("文件不存在，请先创建文件");
  // 内容有变化时才写入历史版本，避免无意义的重复快照
  if (oldContent !== content) await pushHistory(env, filename, oldContent);
  if (token)
    await updateShareCache(
      env,
      token,
      filename,
      content,
      row.results[0].share_expires_at || 0,
    );
  return token;
}

async function deleteFile(env, filename) {
  const isDir = isFolder(filename);
  let items = [];
  if (isDir) {
    const escaped = escapeLike(filename);
    const r = await env.DB.prepare(
      "SELECT token, path FROM files WHERE path = ? OR path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(filename, escaped)
      .all();
    items = r.results
      .map((x) => ({ token: x.token, path: x.path }))
      .filter((t) => t.token);
    await env.DB.prepare(
      "DELETE FROM files WHERE path = ? OR path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(filename, escaped)
      .run();
    await env.DB.prepare(
      "DELETE FROM file_history WHERE path = ? OR path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(filename, escaped)
      .run();
  } else {
    const r = await env.DB.prepare(
      "SELECT token, path FROM files WHERE path = ?",
    )
      .bind(filename)
      .all();
    if (r.results.length && r.results[0].token)
      items.push({ token: r.results[0].token, path: r.results[0].path });
    await env.DB.prepare("DELETE FROM files WHERE path = ?")
      .bind(filename)
      .run();
    await env.DB.prepare("DELETE FROM file_history WHERE path = ?")
      .bind(filename)
      .run();
  }
  for (const t of items) await deleteShareCache(env, t.token, t.path);
  return items;
}

async function renameFile(env, oldName, newName) {
  sanitizePath(oldName);
  sanitizePath(newName);
  if (oldName === newName) return [];
  if (
    (
      await env.DB.prepare("SELECT path FROM files WHERE path = ?")
        .bind(newName)
        .all()
    ).results.length
  )
    throw new Error("目标名称已存在");
  const isDir = isFolder(oldName);
  let tokens = [];
  if (isDir) {
    const od = oldName.endsWith("/") ? oldName : oldName + "/";
    const nd = newName.endsWith("/") ? newName : newName + "/";
    const escapedOd = escapeLike(od);
    const r = await env.DB.prepare(
      "SELECT token, path FROM files WHERE path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(escapedOd)
      .all();
    tokens = r.results
      .map((x) => ({ token: x.token, path: x.path }))
      .filter((t) => t.token);
    await env.DB.prepare(
      "UPDATE files SET path = REPLACE(path, ?, ?), updated_at = unixepoch() WHERE path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(od, nd, escapedOd)
      .run();
    await env.DB.prepare(
      "UPDATE file_history SET path = REPLACE(path, ?, ?) WHERE path LIKE ? || '%' ESCAPE '\\'",
    )
      .bind(od, nd, escapedOd)
      .run();
  } else {
    const r = await env.DB.prepare(
      "SELECT token, path FROM files WHERE path = ?",
    )
      .bind(oldName)
      .all();
    tokens = r.results
      .map((x) => ({ token: x.token, path: x.path }))
      .filter((t) => t.token);
    await env.DB.prepare(
      "UPDATE files SET path = ?, updated_at = unixepoch() WHERE path = ?",
    )
      .bind(newName, oldName)
      .run();
    await env.DB.prepare(
      "UPDATE file_history SET path = ? WHERE path = ?",
    )
      .bind(newName, oldName)
      .run();
  }
  for (const t of tokens) await deleteShareCache(env, t.token, t.path);
  return tokens;
}

async function moveItem(env, itemName, targetFolder) {
  sanitizePath(itemName);
  sanitizePath(targetFolder);
  let target = targetFolder.endsWith("/") ? targetFolder : targetFolder + "/";
  if (isFolder(itemName) && target.startsWith(itemName))
    throw new Error("不能将文件夹移动到自身或其子文件夹中");
  const base = getBaseName(itemName),
    newPath = target + base;
  sanitizePath(newPath);
  if (
    (
      await env.DB.prepare("SELECT path FROM files WHERE path = ?")
        .bind(newPath)
        .all()
    ).results.length
  )
    throw new Error("目标位置已存在同名文件");
  return renameFile(env, itemName, newPath);
}

async function getFileToken(env, filename) {
  return (
    (
      await env.DB.prepare("SELECT token FROM files WHERE path = ?")
        .bind(filename)
        .all()
    ).results[0]?.token || ""
  );
}
async function getShareExpireAt(env, filename) {
  return (
    (
      await env.DB.prepare("SELECT share_expires_at FROM files WHERE path = ?")
        .bind(filename)
        .all()
    ).results[0]?.share_expires_at || 0
  );
}
async function saveFileToken(env, filename, token, expiresAt = null) {
  const old =
    (
      await env.DB.prepare("SELECT token FROM files WHERE path = ?")
        .bind(filename)
        .all()
    ).results[0]?.token || null;
  const res = await env.DB.prepare(
    "UPDATE files SET token = ?, share_expires_at = ?, updated_at = unixepoch() WHERE path = ?",
  )
    .bind(token, expiresAt, filename)
    .run();
  if (res.changes === 0) {
    await env.DB.prepare(
      "INSERT INTO files (path, is_folder, content, token, share_expires_at, created_at, updated_at) VALUES (?, 0, '', ?, ?, unixepoch(), unixepoch())",
    )
      .bind(filename, token, expiresAt)
      .run();
  }
  await setShareCache(
    env,
    token,
    filename,
    await getFileContent(env, filename),
    old,
    expiresAt,
  );
  return { oldToken: old, newToken: token };
}
async function createNewFile(env, fullPath) {
  await env.DB.prepare(
    "INSERT INTO files (path, is_folder, content, token, created_at, updated_at) VALUES (?, 0, '', NULL, unixepoch(), unixepoch())",
  )
    .bind(fullPath)
    .run();
}
async function createNewFolder(env, fullPath) {
  await env.DB.prepare(
    "INSERT INTO files (path, is_folder, content, token, created_at, updated_at) VALUES (?, 1, NULL, NULL, unixepoch(), unixepoch())",
  )
    .bind(fullPath)
    .run();
}
async function proxyFrontend(frontendUrl, request, ctx) {
  // 直接回源，不做本地缓存，确保前端更新后立即可见
  const res = await fetch(frontendUrl, { cf: { cacheEverything: true } });
  return new Response(res.body, {
    status: res.status,
    headers: {
      ...res.headers,
      "Cache-Control": "no-cache",
      "Content-Type": "text/html;charset=utf-8",
      "X-Frame-Options": "DENY",
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    ADMIN_UUID = env.ADMIN_UUID || ADMIN_UUID;
    const url = new URL(request.url);
    const pathname = url.pathname.slice(1);
    // 统一分享链接前缀为 /share/<token>/...
    // 历史格式（/adminsub/...、/admin/sub/...、/sub/...）一律 301 重定向到标准格式
    const redirectShare = (prefix) =>
      "/share/" + pathname.slice(prefix.length) + url.search;
    if (pathname.startsWith("adminsub/"))
      return new Response(null, {
        status: 301,
        headers: { Location: redirectShare("adminsub/") },
      });
    if (pathname.startsWith("admin/sub/"))
      return new Response(null, {
        status: 301,
        headers: { Location: redirectShare("admin/sub/") },
      });
    if (pathname.startsWith("sub/"))
      return new Response(null, {
        status: 301,
        headers: { Location: redirectShare("sub/") },
      });
    const parts = pathname.split("/");
    if (!ADMIN_UUID) return text("⚠️ 请设置环境变量 ADMIN_UUID", 400);
    if (parts[0] === "share" && parts.length >= 3) {
      try {
        const token = parts[1];
        const decodedPath = decodeURIComponent(parts.slice(2).join("/"));
        const kv = await getShareCache(env, token, decodedPath);
        if (kv !== null) {
          if (kv.expireAt && Math.floor(Date.now() / 1000) > kv.expireAt)
            return text("分享链接已过期", 410);
          ctx.waitUntil(putCFCache(request, token, decodedPath, kv.content));
          return text(kv.content);
        }
        await initDB(env);
        const saved = await getFileToken(env, decodedPath);
        if (!saved || !timingSafeEqual(token, saved))
          return text("Token无效或文件不存在", 403);
        const expiresAt = await getShareExpireAt(env, decodedPath);
        if (expiresAt && Math.floor(Date.now() / 1000) > expiresAt)
          return text("分享链接已过期", 410);
        const content = await getFileContent(env, decodedPath);
        ctx.waitUntil(
          Promise.all([
            updateShareCache(env, saved, decodedPath, content, expiresAt),
            putCFCache(request, token, decodedPath, content),
          ]),
        );
        return text(content);
      } catch (e) {
        return text("访问失败：" + e.message, 400);
      }
    }
    if (parts[0] === "share")
      return text("格式错误：/share/<Token>/<路径>/<文件名>", 400);
    await initDB(env);
    if (pathname === "admin" || pathname.startsWith("admin/")) {
      if (
        request.method === "GET" &&
        !url.searchParams.has("action") &&
        !url.searchParams.has("file") &&
        !request.headers.get("X-File-Name")
      ) {
        const frontendUrl = env.FRONTEND_URL || DEFAULT_FRONTEND_URL;
        return proxyFrontend(frontendUrl, request, ctx);
      }
      const body = request.method === "POST" ? await request.text() : "";
      if (body.startsWith("LOGIN|")) {
        // 格式：LOGIN|<ADMIN_UUID>|<turnstile_token（未开启 Turnstile 时可留空）>
        const segs = body.split("|");
        const inp = segs[1] || "";
        const turnstileToken = segs[2] || "";
        if (!timingSafeEqual(inp, ADMIN_UUID)) return text("UUID错误", 401);
        const ip = request.headers.get("CF-Connecting-IP") || "";
        const humanOk = await verifyTurnstile(env, turnstileToken, ip);
        if (!humanOk) return text("人机验证失败，请重试", 401);
        const session = await createSessionToken(env);
        return text("登录成功", 200, {
          "Set-Cookie": `admin_token=${session};Path=/;HttpOnly;SameSite=Lax;Secure;Max-Age=${ADMIN_COOKIE_MAX_AGE}`,
        });
      }
      if (body.startsWith("LOGOUT"))
        return text("已登出", 200, {
          "Set-Cookie": `admin_token=;Path=/;HttpOnly;SameSite=Lax;Secure;Max-Age=0`,
        });
      if (url.searchParams.get("action") === "get_config")
        return json({ turnstile_site_key: env.TURNSTILE_SITE_KEY || "" });
      const adminToken = getCookie(request, "admin_token");
      if (!(await verifySessionToken(env, adminToken)))
        return text("未登录", 401);
      if (url.searchParams.get("action") === "get_tree")
        return json(await getFileList(env));
      if (body.startsWith("FILE_TOKEN|")) {
        // 格式：FILE_TOKEN|<文件名>|<自定义token，可空>|<有效期小时数，0或空=长期有效>
        const [_, filename, custom, expire] = body.split("|");
        if (!filename) return text("缺少文件名", 400);
        const expireHours = parseInt(expire, 10);
        const expiresAt =
          Number.isFinite(expireHours) && expireHours > 0
            ? Math.floor(Date.now() / 1000) + expireHours * 3600
            : null;
        const result = await saveFileToken(
          env,
          filename,
          custom?.trim() || uuidv4(),
          expiresAt,
        );
        if (result.oldToken && result.oldToken !== result.newToken) {
          ctx.waitUntil(purgeCFCache(request, result.oldToken, filename));
        }
        return text(await getFileToken(env, filename));
      }
      if (body.startsWith("GET_TOKEN|")) {
        // 返回格式：<token>|<过期时间戳(秒)，0=长期有效>；未生成 token 时返回提示文案
        const [_, filename] = body.split("|");
        if (!filename) return text("缺少文件名", 400);
        const token = await getFileToken(env, filename);
        if (!token) return text("该文件未生成Token");
        return text(token + "|" + (await getShareExpireAt(env, filename)));
      }
      if (body.startsWith("FILE_OP|")) {
        try {
          const [_, op, ...args] = body.split("|");
          switch (op) {
            case "new": {
              const full = (args[1] || "") + args[0]?.trim();
              sanitizePath(full);
              if (
                (
                  await env.DB.prepare("SELECT path FROM files WHERE path = ?")
                    .bind(full)
                    .all()
                ).results.length
              )
                throw new Error("文件已存在");
              await createNewFile(env, full);
              return json({ success: true, path: full });
            }
            case "newfolder": {
              let fn = args[0]?.trim();
              if (!fn) throw new Error("文件夹名不能为空");
              const full = (args[1] || "") + (fn.endsWith("/") ? fn : fn + "/");
              sanitizePath(full);
              if (
                (
                  await env.DB.prepare("SELECT path FROM files WHERE path = ?")
                    .bind(full)
                    .all()
                ).results.length
              )
                throw new Error("文件夹已存在");
              await createNewFolder(env, full);
              return json({ success: true, path: full });
            }
            case "delete": {
              const items = await deleteFile(env, args[0]);
              ctx.waitUntil(
                Promise.all(
                  items.map((t) => purgeCFCache(request, t.token, t.path)),
                ),
              );
              return text("删除成功");
            }
            case "rename": {
              const items = await renameFile(env, args[0], args[1]);
              ctx.waitUntil(
                Promise.all(
                  items.map((t) => purgeCFCache(request, t.token, t.path)),
                ),
              );
              return text("重命名成功");
            }
            case "move": {
              const items = await moveItem(env, args[0], args[1]);
              ctx.waitUntil(
                Promise.all(
                  (items || []).map((t) =>
                    purgeCFCache(request, t.token, t.path),
                  ),
                ),
              );
              return text("移动成功");
            }
            case "history_list": {
              // args[0] = 文件路径；返回该文件最近的历史版本列表（不含内容，节省带宽）
              const filename = args[0];
              sanitizePath(filename);
              const r = await env.DB.prepare(
                "SELECT id, saved_at FROM file_history WHERE path = ? ORDER BY saved_at DESC, id DESC LIMIT ?",
              )
                .bind(filename, MAX_HISTORY)
                .all();
              return json(r.results);
            }
            case "history_get": {
              // args[0] = 文件路径, args[1] = 历史版本 id；返回该版本内容
              const filename = args[0];
              sanitizePath(filename);
              const id = parseInt(args[1], 10);
              if (!Number.isFinite(id)) throw new Error("版本ID无效");
              const r = await env.DB.prepare(
                "SELECT id, content, saved_at FROM file_history WHERE id = ? AND path = ?",
              )
                .bind(id, filename)
                .all();
              if (!r.results.length) throw new Error("历史版本不存在");
              return json(r.results[0]);
            }
            case "history_restore": {
              // args[0] = 文件路径, args[1] = 历史版本 id；将当前内容也存入历史后回滚
              const filename = args[0];
              sanitizePath(filename);
              const id = parseInt(args[1], 10);
              if (!Number.isFinite(id)) throw new Error("版本ID无效");
              const hr = await env.DB.prepare(
                "SELECT content FROM file_history WHERE id = ? AND path = ?",
              )
                .bind(id, filename)
                .all();
              if (!hr.results.length) throw new Error("历史版本不存在");
              const targetContent = hr.results[0].content || "";
              const used = await saveFileContent(env, filename, targetContent);
              if (used)
                ctx.waitUntil(putCFCache(request, used, filename, targetContent));
              return json({ success: true });
            }
            case "history_delete": {
              // args[0] = 文件路径, args[1] = 历史版本 id；删除指定历史版本
              const filename = args[0];
              sanitizePath(filename);
              const id = parseInt(args[1], 10);
              if (!Number.isFinite(id)) throw new Error("版本ID无效");
              const r = await env.DB.prepare(
                "DELETE FROM file_history WHERE id = ? AND path = ?",
              )
                .bind(id, filename)
                .run();
              if (r.meta.changes === 0) throw new Error("历史版本不存在");
              return json({ success: true });
            }
            default:
              return text("未知操作", 400);
          }
        } catch (e) {
          return text(e.message, 400);
        }
      }
      if (
        request.method === "POST" &&
        !body.startsWith("FILE_TOKEN|") &&
        !body.startsWith("GET_TOKEN|") &&
        !body.startsWith("FILE_OP|") &&
        !body.startsWith("LOGIN|") &&
        !body.startsWith("LOGOUT")
      ) {
        let filename = decodeURIComponent(
          request.headers.get("X-File-Name") || "",
        );
        if (!filename) return text("缺少文件名", 400);
        sanitizePath(filename);
        const inlineToken = request.headers.get("X-File-Token")
          ? decodeURIComponent(request.headers.get("X-File-Token"))
          : null;
        try {
          const used = await saveFileContent(env, filename, body, inlineToken);
          if (used) ctx.waitUntil(putCFCache(request, used, filename, body));
          return text("保存成功");
        } catch (e) {
          return text(e.message, 400);
        }
      }
      if (url.searchParams.get("action") === "get_content") {
        return text(
          await getFileContent(
            env,
            decodeURIComponent(url.searchParams.get("file") || ""),
          ),
        );
      }
      const frontendUrl = env.FRONTEND_URL || DEFAULT_FRONTEND_URL;
      return proxyFrontend(frontendUrl, request, ctx);
    }
    return text("Not Found", 404);
  },
};
