# SSL 自动签发、续期与补发脚本

[English](ssl-automation.md) | [简体中文](ssl-automation.zh-CN.md)

`scripts/ssl_manage.py` 将已有服务器上的证书管理流程整理为可配置实现：调用已安装的 `acme.sh`，负责候选校验、历史备份、Nginx 检查、平滑重载、源站 TLS 验证和事务恢复。

## 适用条件

- Linux，支持同文件系统的 `renameat2` 原子目录交换，架构为 x86-64 或 AArch64。
- Python 3.6+ 标准库、OpenSSL 1.1.1+（支持 `verify -no_check_time`），以及已完成账户和 DNS 插件配置的 `acme.sh`。
- 当前仅支持 RSA 2048 证书组；不支持其他密钥位数、ECC 账户目录或通配符登记。
- 原生或 Docker Nginx，通过管理员维护的命令参数数组选择，不经过 shell 拼接执行。
- 每个证书组有独立线上目录。发布只交换证书组子目录，不替换容器挂载的证书根目录。

脚本不安装 ACME、不创建 DNS 凭据、不生成业务路由，也不会自动迁移已有证书布局。现有系统已经可靠时，优先复用，不为了套用示例替换它。

## 目录示例

```text
/srv/
├── nginx/
│   ├── cert/example.com/
│   │   ├── fullchain.pem
│   │   └── privkey.pem
│   └── ssl/
│       ├── staging/example.com/
│       └── state/transactions/
├── nginx-logs/ssl-renew/
├── nginx-backups/cert/example.com/
│   └── YYYY-MM-DD_HH-MM-SS__cert/
│       ├── payload/
│       ├── manifest.json
│       └── SHA256SUMS
└── nginx-work/ssl/
```

路径需要按现场调整，使用不含符号链接组件的绝对路径，例如系统将 `/var/run` 链接到 `/run` 时应使用后者。Nginx、ACME、日志、备份和工作区五个根目录不得互相嵌套；锁文件位于这些根之外，父目录须已存在。工作区与线上证书组必须在同一文件系统，证书组本身不能是直接 bind mount 的挂载根。

## 配置

从 [certificates.example.json](../examples/ssl/certificates.example.json) 开始，按现场修改路径、域名、端口和命令，保存到受限配置文件，例如 `/etc/nginx-ops/certificates.json`，权限设为 `0600`。

原生 Nginx 可以将示例中的 Docker 命令替换为：

```json
{
  "nginx_test_command": ["nginx", "-t"],
  "nginx_reload_command": ["systemctl", "reload", "nginx"]
}
```

配置与脚本属于受信管理代码，不能让应用用户修改命令数组、证书路径、备份或事务。

DNS 提供商使用已安装 ACME 客户端支持的插件。示例选择 `dns_ali`，凭据或插件支持的工作负载身份在仓库之外配置，按提供商文档接入。脚本不更改现有账户的 CA 或全局默认 CA。

接管已有证书前，先审查客户端的安装目标和 hook。`configure` 只接受空或安全的 staging 安装目标，以及空 hook；发现已有线上安装目标或 reload hook 会拒绝执行。先备份并明确迁移冲突设置，不静默接管另一条发布链。

## 只读检查

所有命令都要明确传入配置：

```bash
python3 scripts/ssl_manage.py --help
python3 scripts/ssl_manage.py plan --config /etc/nginx-ops/certificates.json
python3 scripts/ssl_manage.py status --config /etc/nginx-ops/certificates.json
```

`plan` 读取本地状态；`status` 额外按 SNI 和端口验证源站实际证书。两者不签发、不发布，也不能替代业务登录或真实支付验证。

## 根据问题选择操作

| 情况 | 处理 |
|---|---|
| staging 已有更新的有效证书，线上未换 | `reconcile` 先发布候选，再判断续期时机 |
| 临近到期或 ACME 已到续期时间 | `reconcile` 正常续期，校验后发布 |
| staging 候选有效但比线上证书更旧 | 保留更新的线上证书，到期时正常续期，或显式 `reissue` |
| 正常续期时间之前，明确需要 CA 补发 | 显式 `reissue`，不放入定时任务 |
| 新增证书组 | 先 `enroll --dry-run`，再确认签发并配置站点引用 |
| 线上证书缺失、不成对或被其他操作修改 | 先检查并恢复/核对，不盲目覆盖 |

### 接管已有 ACME 证书组

先按上述目录布局在配置中登记证书组和完整 SAN，再执行：

```bash
python3 scripts/ssl_manage.py configure \
  --config /etc/nginx-ops/certificates.json --cert example.com
```

这是写操作，为已经审阅的 ACME 证书组配置 staging。先备份原客户端配置和证书对；已有线上安装目标或部署 hook 时，必须先明确迁移冲突设置，程序不会直接覆盖它们。

### 新增签发

```bash
python3 scripts/ssl_manage.py enroll \
  --config /etc/nginx-ops/certificates.json \
  --cert example.com --san www.example.com --dry-run

python3 scripts/ssl_manage.py enroll \
  --config /etc/nginx-ops/certificates.json \
  --cert example.com --san www.example.com
```

新增只准备证书和登记，不创建 `server_name`、代理路由或证书指令。配置站点引用并完成验证后，再启用定时协调。

### 自动续期

```bash
python3 scripts/ssl_manage.py reconcile \
  --config /etc/nginx-ops/certificates.json
```

按现场调整 [renew.cron](../examples/ssl/renew.cron)，启用前创建受限日志目录。只保留一条协调发布的调度链，避免原 ACME 定时任务和包装程序各自写线上证书。示例每天检查四次，不等于每天强制签发四次。

### 明确补发

```bash
python3 scripts/ssl_manage.py reissue \
  --config /etc/nginx-ops/certificates.json --cert example.com
```

这会真实请求 CA 提前重新签发，可能消耗签发额度或触发限流。它与“把已经签好的证书安装上线”是两种操作；若客户端未产生指纹不同且到期时间更晚的替换证书，命令会明确报失败并保留线上证书。定时任务不默认强制补发。

## 发布与恢复

程序使用共享锁，记录 `prepared`、`switched`、`committed` 等阶段。发布前校验 SAN、有效期、信任链和私钥匹配，备份旧证书并校验，然后原子交换整个证书组、检查 Nginx、平滑重载并核对源站指纹。

失败时恢复旧证书对，另外记录旧证书是否仍提供有效 TLS。下次写操作先恢复中断事务。备份损坏、线上证书被外部修改、不支持原子交换或恢复失败时停止发布。

显式回滚只接受仍与线上版本对应的已提交事务：

```bash
python3 scripts/ssl_manage.py rollback \
  --config /etc/nginx-ops/certificates.json --transaction TRANSACTION_ID
```

事务关联的历史证书必须保留。单独备份 Nginx 根目录可能漏掉外部历史和 ACME 账户。后续协调可能重新发布更新的有效候选，所以回滚不等于永久停止续期。

## 日期与日志

备份目录及单次运行日志采用 `YYYY-MM-DD_HH-MM-SS`，manifest 记录带偏移量时间和时区。示例为 `Asia/Shanghai` 与 `+08:00`，调整时保持两者一致；实现使用固定偏移量，不自动处理 IANA 时区的夏令时。含密钥的日志/备份保持受限权限，不自动删除历史证书。

连续追加的 cron 日志需要单独配置轮转；接入证书自动化不代表所有程序日志已经自动轮转。单次操作日志只记录元数据和退出码，不保存 ACME 外部输出，避免 DNS 插件打印凭据；需要排查客户端细节时，在管理员受控会话中单独诊断。

## 本地验证

```bash
python3 -m unittest discover -s tests -v
```

测试使用临时目录、临时证书和本地 mock，不请求真实 CA、不连接生产服务器，也不重载真实 Nginx。部署前仍要结合目标系统及 ACME 客户端版本完成适配验证。
