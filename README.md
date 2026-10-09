# 域名与 SSL 证书管理平台（Python）

一个自托管的网页工具：管理主域名与子域名、保存阿里云 AccessKey，按 acme.sh 的 `dns_ali` 思路自动
申请 / 续期 / 下载 SSL 证书。底层用 Let's Encrypt 官方 Python 库 `python-acme` 走 ACME v2 的
**DNS-01（阿里云 TXT）** 验证，因此**不需要对外开放 80/443 端口**，也支持 `*.example.com` 泛域名。

| acme.sh | 本项目 |
| --- | --- |
| `--dns dns_ali` + `Ali_Key/Ali_Secret` | 网页里录入的阿里云凭证（Secret 加密存储） |
| `--server` / `--staging` | 设置 → CA（生产 / Staging / ZeroSSL / 自定义目录） |
| `--keylength 2048` | 申请时选择密钥类型（RSA 2048/4096、ECDSA P-256/384） |
| `acme.sh --issue -d ... -d '*.example.com'` | 勾选主机记录 → 申请证书 |
| `cron.sh` 每日自动续期 | 内置 APScheduler，默认每天 03:10 检查并续期 |
| `--install-cert` / `--deploy` | 下载 fullchain.pem / privkey.pem / .pfx / .cer / zip（部署仍是你自己的事） |

---

## 1. 本机运行（Windows，环境已备好）

依赖已经装在项目的 `.venv` 里（pip 源用的阿里云镜像），直接启动：

```powershell
cd E:\projects\python\acme
.venv\Scripts\python.exe run.py
```

浏览器打开 <http://127.0.0.1:8000> → 第一次会进入初始化页，设置管理密码（≥10 位）→ 登录。

### 改监听端口 / 地址

优先级：**命令行参数 > 环境变量 > `.env` > 默认值（127.0.0.1:8000）**。

```powershell
.venv\Scripts\python.exe run.py --port 9000              # 只换端口
.venv\Scripts\python.exe run.py --host 0.0.0.0 --port 9000
.venv\Scripts\python.exe run.py --help                   # 看所有参数
```

也可以用环境变量或 `.env`（复制 `.env.example` 为 `.env`）：

```ini
ACME_HOST=127.0.0.1
ACME_PORT=9000
```

> `--host 0.0.0.0` 会把界面暴露在所有网卡上，只在确实需要局域网访问时用，并且务必用防火墙限定来源 IP；
> 正常情况下保持 `127.0.0.1`，由 Nginx/宝塔反向代理对外提供 HTTPS。
> 端口被占用时启动会报 `[Errno 98] Address already in use`，换端口或结束占用进程即可。

重装依赖（换机器或 Python 版本变化时）：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt
```

> 本机测试用的是 `data/` 目录下的 SQLite 库和自动生成的 `data/master.key`，不需要额外配置。

## 2. 申请第一张证书

1. **建一个只有 DNS 权限的 RAM 用户**（不要用主账号 AccessKey）
   阿里云控制台 → RAM 访问控制 → 用户 → 创建用户（勾选“OpenAPI 调用访问”）→ 附加自定义权限：

   ```json
   {
     "Version": "1",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "alidns:AddDomainRecord",
           "alidns:UpdateDomainRecord",
           "alidns:DeleteDomainRecord",
           "alidns:DescribeDomainRecords"
         ],
         "Resource": "acs:alidns:*:<你的账号ID>:domain/example.com"
       },
       { "Effect": "Allow", "Action": ["alidns:DescribeDomains"], "Resource": "*" }
     ]
   }
   ```

   管理多个域名时，把 `Resource` 里的域名换成数组，或直接授予多个 `domain/*`。

2. **阿里云凭证**页 → 填名称、AccessKeyId、AccessKeySecret → 保存 → 点「测试并列出域名」。
   列出域名就说明 Key 可用。Secret 用主密钥派生的 AES-256-GCM 加密后才写库，页面只显示 `LTAI****GHIJ`。

3. **域名与子域名**页 → 填主域名（`example.com`，不要填 `www`）→ 选凭证 → 添加。
   自动创建 `@`（example.com）与 `*`（*.example.com）两条主机记录。
   可以点「从阿里云导入现有解析记录」把已有记录的名称一次性拉进来（只导入名字，默认不勾选）。

4. 在域名页勾选要签发的名字 → 选密钥类型 → **申请证书**。
   页面会跳到证书详情，实时显示每一步日志：注册/复用 ACME 账号 → 生成 CSR → 提交订单 → 添加 TXT →
   等待生效 → CA 校验 → 下载证书链 → 清理 TXT。

   ⚠️ 勾选时注意 CA 的规则（实测 Let's Encrypt）：`*.example.com` 与 `www.example.com` **不能同批**，
   会被判定冗余而拒绝订单；`*.example.com` + `example.com` 可以，`*.example.com` + `a.b.example.com` 也可以。
   冲突时页面会直接标红并说明取消哪一个。

5. 证书页 → **下载**。`fullchain.pem`（站点用）、`privkey.pem`（私钥）、`chain.pem`（仅中间证书）、
   `.pfx`（IIS，密码在“设置 → PFX 导出密码”里填）、`.cer`（DER）、zip 全打包。

## 3. 自动续期与到期提醒

- 设置页里「剩余多少天自动续期」默认 30 天，每天 03:10 检查一次，命中就重新签发（同一张证书记录，文件覆盖更新）。
- 服务启动 45 秒后先补跑一次，避免刚部署完等到半夜。
- 一个证书记录同时只允许一个任务在跑；进程被杀导致停在“申请中”的记录，重启时会自动标记为失败。
- 想先试水不影响生产额度：设置 → CA 选 **Let's Encrypt Staging**（浏览器不信任，但限额宽松），
  跑通后切回生产。设置页有「测试 CA 连接并注册账号」按钮。
- 邮件提醒：填 SMTP（阿里云企业邮、QQ/163 的授权码都可以）→ 打开「提醒开关」→「发送测试邮件」。
  签发失败、以及剩余天数低于「告警天数」时发信（每张证书每天最多一封）。

## 4. 部署到宝塔面板（Linux）

### 4.1 准备

- 目标域名已托管在**阿里云云解析 DNS**，且域名的 NS 指向 `*.alidns.com`。
- 服务器能**出站**访问 443（DNS-01 不需要任何入站端口，也不需要 ICP 备案的 Web 服务）。
- Python **≥ 3.10**（`acme 5.x` 硬性要求）。宝塔「Python 项目管理器」→「版本管理」里装 3.10/3.11/3.12；
  如果列表里没有，先在软件商店升级项目管理器，或手动装对应 Python。

### 4.2 上传代码并建项目

1. 把本项目源码上传到 `/www/wwwroot/acme`，**不要**上传 `.venv/`、`data/`、`.env`（这几个是本机的测试状态）。
2. 宝塔 → 软件商店 → **Python 项目管理器** → 添加项目：
   - 项目路径 `/www/wwwroot/acme`，Python 版本选 3.10+，框架 FastAPI，启动方式 **uvicorn**
   - 端口 `8000`，**项目进程数 = 1**（关键：多 worker 会各自启动一个调度器，导致重复签发、触发 CA 限流）
   - 若项目管理器让你填启动命令，用 `python run.py`（它内部就是单 worker 的 uvicorn）；
     要换端口就在启动参数里加 `--port 9000`，或写进项目的 `.env`（`ACME_PORT=9000`），两边保持一致
     —— 反向代理的目标端口要和这里对齐。
3. 在项目目录安装依赖（项目管理器有“依赖包”页，或命令行执行）：

   ```bash
   cd /www/wwwroot/acme
   # 用项目管理器给该项目建好的 venv 里的 pip（宝塔一般放在 /www/server/pyporject_evn/<项目名>_venv/bin/pip，
   # 具体路径看项目管理器“项目设置 → 虚拟环境”里显示的路径）
   <项目venv>/bin/pip install -i https://mirrors.aliyun.com/pypi/simple/ -r requirements.txt
   # 或者：pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
   ```

4. 生成 `.env`（宝塔项目一般不给环境变量界面，用文件即可）：

   ```bash
   cat > /www/wwwroot/acme/.env <<'EOF'
   ACME_HOST=127.0.0.1
   ACME_PORT=8000
   ACME_COOKIE_SECURE=1
   EOF
   chmod 600 /www/wwwroot/acme/.env
   # 强烈建议再生成一个固定主密钥（丢失就要重录 AccessKeySecret）：
   # ACME_MASTER_KEY=<openssl rand -hex 32 的输出>
   ```

5. 收紧权限（证书私钥都在这里）：

   ```bash
   chown -R www:www /www/wwwroot/acme
   chmod 700 /www/wwwroot/acme/data
   ```

### 4.3 对外访问（只走 HTTPS，不要开 8000）

1. 宝塔 → 网站 → 添加站点，例如 `cert.example.com`（PHP/静态都行，只当壳）。
2. 站点设置 → **反向代理** → 目标 URL `http://127.0.0.1:8000`，发送域名 `$host`。
3. 站点设置 → **SSL 证书** → 先用 Let's Encrypt HTTP-01 或本工具自己签一张，开启 **强制 HTTPS**。
   （开启后把 `.env` 的 `ACME_COOKIE_SECURE` 设为 1，否则浏览器不回传登录 Cookie。）
4. 宝塔「安全」+ 阿里云“安全组”里**不要**放行 8000 端口，只留 80/443。
5. 想再加一层：站点设置 → 目录保护（Basic Auth），或 Nginx 里只允许办公网 IP `allow/deny`。

### 4.4 部署后要做的 6 件事

1. 打开管理域名 → 初始化密码 → 登录。
2. 添加阿里云凭证 → 点「测试并列出域名」→ 确认真能读到账号里的域。
3. 设置页 → CA 先选 **Staging** → 点「测试 CA 连接并注册账号」→ 确认可达（国内服务器偶发连不上 LE，
   这一步能立刻发现；不行就换 ZeroSSL 或自定义目录）。
4. 挑一个不重要的域名用 Staging 走一遍完整申请（含 TXT 等待、日志、下载），验证成功再切生产 CA。
5. 填 SMTP、打开「提醒开关」→ 发送测试邮件 → 确认证书快到期时你收得到。
6. 加备份计划任务：宝塔 → 计划任务 → Shell 脚本，每天打包 `data/`：

   ```bash
   tar czf /www/backup/acme-$(date +%F).tar.gz -C /www/wwwroot/acme data
   ```

   `data/` 里有三样缺一不可：`acme.db`（域名/证书记录）、`certs/`（证书与私钥）、`master.key`（解密用）。
   **异地备份 master.key**：它丢了，所有 AccessKeySecret 要重新录；私钥丢了，重新签一张即可。

## 5. 把证书用到别处

- **宝塔站点（Nginx）**：站点 → SSL 证书 → “其它” → 粘贴 `fullchain.pem` 内容到“证书”、`privkey.pem` 到“密钥” → 保存并启用。
- **IIS / Windows**：下载 `.pfx`（先设置 PFX 密码），双击导入证书存储后在绑定里选择。
- **阿里云 CDN/DCDN/SLB/WAF**：用 `cert.pem` + `privkey.pem` 在控制台上传，或用 `aliyun cas UploadUserCertificate`。
- **其它服务器**：`zip` 打包下载，`scp` 走安全通道传输（不要发到公网可达的位置）。
- 泛域名证书 `*.example.com` 只覆盖**一级**子域名且不含 `example.com` 本身，所以申请时把 `@` 一起勾上。

## 6. 常见报错

| 页面提示 | 处理办法 |
| --- | --- |
| `AccessKeyId 不存在或填错` / `AccessKeySecret 不正确` | 核对 RAM 里的 Key；改过 Secret 要在凭证页重新填；服务器时间偏差大也会签名失败（`ntpdate`） |
| `RAM 权限不足` | 用上面第 2 节的策略；注意 `DescribeDomains` 不能限具体资源 |
| `该域名不在当前阿里云账号下` | 域名托管在另一个账号，或填成了子域名（要填主域名） |
| `TXT 迟迟没有生效` | 阿里云免费版 TTL 最小 600s，把「等待 TXT 生效」调到 300～600；确认 NS 是 `*.alidns.com`；**同一域名不能同时在别家 DNS 解析**，否则 CA 可能读到旧数据 |
| `CA 错误：… dns …` | CA 侧解析失败，多为 NS 不对或域名未托管在阿里云 |
| `CA 错误：… caa …` | 删除域名的 CAA 记录，或加 `0 issue "letsencrypt.org"`（用 ZeroSSL 则是 `letsencrypt.org` 对应的 CA 名） |
| `CA 错误：… rateLimited …` | Let's Encrypt 同一批域名每周 50 张；测试请改 Staging；确认自动续期没被反复触发 |
| `无法访问 CA 目录` | 出站被拦或国内到 LE 不稳：先试 Staging，再考虑换 CA 目录；检查防火墙是否放行 443 出站 |
| `通配符 *.example.com 已经覆盖 www.example.com` | 页面已拦，取消勾选其中一个 |
| `无法解密已保存的 AccessKeySecret` | `master.key`/`ACME_MASTER_KEY` 变了：去凭证页重录 Secret |

## 7. 安全设计要点

- AccessKeySecret：`PBKDF2-HMAC-SHA256(200k 次) → AES-256-GCM`，密文入库；界面与日志只出现指纹。
- 证书私钥文件 `chmod 600`（Linux）；下载响应带 `Cache-Control: no-store`。
- 登录：`scrypt` 口令散列；HttpOnly + SameSite=Lax Cookie（可加 Secure），改密即让所有旧会话失效；
  同一 IP 连续 8 次失败锁定 10 分钟（走宝塔反代时源 IP 恒为 127.0.0.1，属于全局锁定，正好挡住爆破）。
- 所有表单 POST 都校验 CSRF token；模板全量自动转义；SQL 全参数化。
- 下载接口的文件路径由数据库主键推导，`kind` 只接受白名单值，不接受任意路径。
- 只应通过 HTTPS 或内网访问；不要把 8000 直接暴露公网。

## 8. 代码结构与测试

```
app/
  config.py     环境变量 / .env / 数据目录 / 主密钥
  crypto.py     AES-GCM 加密、scrypt 口令、签名 Cookie
  db.py         SQLite 结构 + 设置项
  repo.py       凭证 / 域名 / 主机记录 / 证书 / 日志的数据访问
  names.py      域名与主机记录换算、泛域名冗余检查
  alidns.py     阿里云解析 OpenAPI + TXT 生效检测（权威 NS 优先）
  issuer.py     ACME dns-01 全流程（python-acme）
  certstore.py  密钥/CSR/PEM/PFX/DER 与证书文件落盘
  service.py    编排：状态机、后台任务、续期窗口、提醒
  scheduler.py  APScheduler 定时任务
  notify.py     SMTP 到期/失败提醒
  auth.py       登录、会话、CSRF
  web.py        FastAPI 路由 + 页面
  templates/ static/
run.py          启动入口（uvicorn 单进程）
tests/          100 个离线用例 + 2 个需联网的 Let's Encrypt Staging 用例
```

```powershell
.venv\Scripts\python.exe -m pytest tests/ -q                  # 离线，全部不联网
ACME_RUN_NET=1 .venv\Scripts\python.exe -m pytest tests/test_acme_staging.py -q   # 会真实注册 staging 账号
```

## 9. 已知限制

- DNS 服务商只支持阿里云（要加别家：改 `app/alidns.py` 的记录增删查与 `issuer.py` 的调用点）。
- 只做 DNS-01，不做 HTTP-01；不代替 Nginx/CDN 的证书部署动作。
- 单用户，没有角色、审计日志和多租户。
- 「从阿里云导入解析记录」只读，本平台不会修改或删除你已有的解析记录，只增删 `_acme-challenge` TXT。
- 证书有效期由 CA 决定（目前 90 天）。CA/B 论坛已决定逐步缩短到 2029 年 100 天以内，所以自动化是刚需，
  续期阈值别设太大。
