## Text Disk - 轻量文本云盘

基于 Cloudflare 生态的在线文本存储与分享工具，无需服务器。支持文件管理、分享链接、历史版本对比、Turnstile 人机验证。

## 核心特性

- 文件管理 — 创建、编辑、重命名、移动、删除文件和文件夹，右键菜单快捷操作
- 在线编辑 — 内置代码编辑器，支持语法高亮风格的等宽字体，Ctrl+F 内容搜索
- 文件分享 — 生成分享链接 + 二维码，可自定义 Token，支持访客只读访问
- 历史版本 — 自动保存最近 5 个历史版本，支持查看、左右对比（Git 风格 diff）、回滚、删除
- 安全加固 — HMAC-SHA256 会话 Token，恒定时间字符串比较，路径穿越防御，LIKE 转义
- 人机验证 — 可选 Cloudflare Turnstile，登录时校验
- 文件树搜索 — 侧边栏实时过滤文件名，自动展开匹配目录
- 全部展开/收起 — 一键展开或收起文件树中的所有文件夹
- 深色主题 — 响应式布局，桌面端和移动端均可使用

## 架构

| 组件 | 技术 |
|------|------|
| 后端 | Cloudflare Workers（JavaScript） |
| 数据库 | Cloudflare D1 |
| 缓存 | Cloudflare KV（可选，加速分享访问） |
| 前端 | 纯静态 HTML 单文件，部署到 Cloudflare Pages |
| 验证 | Cloudflare Turnstile（可选） |

## CLI部署

### 1. Cloudflare 账号

注册 [Cloudflare](https://dash.cloudflare.com/) 账号，开启 Workers 和 Pages 功能。

### 2. 创建 D1 数据库

```bash
# 安装 wrangler CLI
npm install -g wrangler

# 登录
wrangler login

# 创建 D1 数据库
wrangler d1 create text-disk-db
```

### 3. 创建 KV 命名空间（推荐）

```bash
wrangler kv:namespace create SHARE_KV
```

### 4. 申请 Turnstile（可选）

访问 [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile) 添加站点，获取 Site Key 和 Secret Key。

## 部署方式

### 部署后端 Worker

1. 打开 Cloudflare Dashboard → Workers 和 Pages → 创建 → 创建 Worker
2. 将项目中的 `_worker.js` 内容粘贴到在线编辑器
3. 进入 Worker 设置 → 绑定：
   - **D1 数据库绑定**：变量名称 `DB`，选择上面创建的数据库
   - **KV 命名空间绑定**：变量名称 `SHARE_KV`，选择上面创建的命名空间
4. 进入 Worker 设置 → 变量 → 环境变量，添加：

| 变量名 | 必填 | 说明 |
|--------|------|------|
| `ADMIN_UUID` | 是 | 管理员登录密钥，自行生成一个复杂字符串 |
| `SESSION_SECRET` | 否 | 会话签名密钥，不填则退化使用 ADMIN_UUID |
| `TURNSTILE` | 否 | 设为 `"true"` 开启人机验证 |
| `TURNSTILE_SECRET_KEY` | 否 | 开启 Turnstile 时必填，Turnstile Secret Key |
| `FRONTEND_URL` | 否 | 前端 Pages 地址，用于分享链接拼接 |

5. 点击「保存并部署」

### 部署前端 Pages

1. 打开 Cloudflare Dashboard → Workers 和 Pages → 创建 → Pages
2. 上传项目中的 `frontend/index.html`
3. 部署完成后，将 Pages 地址填入 Worker 的 `FRONTEND_URL` 环境变量（可选，用于分享链接使用正确域名）
4. 如需开启 Turnstile，在前端代码中修改 `TURNSTILE_SITE_KEY` 为你的 Site Key

### 本地开发

```bash
# 启动本地预览
python3 -m http.server 8000 --directory frontend

# 或使用 wrangler 本地调试 Worker
wrangler dev
```

## 项目结构

```
text-disk/
├── README.md          # 项目说明
├── _worker.js          # Cloudflare Worker 后端代码
└── frontend/
    └── index.html      # 前端单文件页面
```

## 开源协议

基于 GPLv3 协议开源，仅供学习使用，请勿用于非法用途。

---

如果这个项目对你有帮助，欢迎点亮 Star 和 Fork！
**
