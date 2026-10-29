# nginx-ops-skill

[English](README.md) | [简体中文](README.zh-CN.md)

一个面向 AI 编程助手的服务器 Nginx 运维技能，覆盖配置整理、虚拟主机隔离、TLS 证书自动化、日志轮转、备份恢复和变更验证，适用于原生与 Docker 部署。

仓库提供操作方法、可选只读检查工具，以及调用现有 `acme.sh` 的可配置 Linux SSL 自动化脚本，不安装 Nginx 或创建服务器。

## 覆盖范围

- 盘点真实运行服务、配置入口、挂载、定时任务和部署源。
- 区分应用公开根、在线文件、备份、历史归档和工作目录。
- 按校验备份、候选检查、平滑重载、前后对比的顺序实施变更。
- 自动协调 ACME 候选、正常续期和显式补发，配合证书备份校验、原子发布与事务恢复。
- 规划日志重开、旧文件写入检查、压缩校验和明确的保留策略。
- 保护容器挂载根目录，区分 SPA 首页兜底与真实跨站文件暴露。

## 演示效果

将混放的在线文件与历史备份，整理为职责清晰的配置、证书、日志和恢复目录。

![Nginx 目录整理前后对比](assets/directory-layout.png)

## 安装

将本目录复制到所使用助手支持的技能目录。助手需要支持带 YAML 元信息的 `SKILL.md`；如何发现与重新加载技能，以对应工具的文档为准。

保持 `SKILL.md`、`references/`、`scripts/` 和 `examples/` 的相对位置不变。若宿主支持 `~/.agents/skills/`，可将本仓库复制或链接为 `~/.agents/skills/nginx-ops-skill`；其他宿主使用其文档规定的目录。覆盖已有安装前先检查内容。

## 使用

请求示例：

> 只读检查 SSH 别名 prod-web-2 上的 Nginx，给我一份目录整理方案。

> 检查 TLS 续期和回滚条件，不签发证书、不重载服务。

> 核对大日志和现有保留策略，再给出轮转方案。

可选检查脚本要求显式传入已有 SSH 别名：

```bash
bash scripts/inspect.sh --ssh prod-web-2
bash scripts/inspect.sh --ssh prod-web-2 --container nginx
```

脚本依赖 Bash、OpenSSH 和远端基础系统工具。容器检查需要远端安装 Docker，并有权访问指定容器。脚本不会自动安装缺失工具。

## SSL 自动化

[脚本说明](references/ssl-automation.zh-CN.md)包含管理程序、[配置示例](examples/ssl/certificates.example.json)和[定时任务示例](examples/ssl/renew.cron)。

```bash
# 只读检查本地状态，不签发、不发布
python3 scripts/ssl_manage.py plan --config /etc/nginx-ops/certificates.json

# 正常定时协调：先发布已有新候选，再按到期条件续期
python3 scripts/ssl_manage.py reconcile --config /etc/nginx-ops/certificates.json

# 明确要求 CA 提前补发某个证书组
python3 scripts/ssl_manage.py reissue --config /etc/nginx-ops/certificates.json --cert example.com
```

使用写命令前，按现场配置路径、DNS 插件、信任和 Nginx 命令。当前实现针对 Linux 原子目录交换和 RSA 证书组，区分候选与线上材料，校验证书对、备份旧版，并在平滑重载后验证源站 TLS。定时任务使用 `reconcile`，不默认强制补发。

## 仓库结构

```text
SKILL.md                 技能入口与工作流程
references/              按主题组织的操作参考
scripts/inspect.sh       可选只读检查工具
scripts/ssl_manage.py    可配置证书自动化程序
examples/ssl/            证书登记和续期调度示例
tests/                   SSL 流程隔离测试
assets/                  目录整理前后对比图
evals/evals.json         行为验证示例
```

## 变更边界

只读请求保持只读。签发、创建备份、轮转、重载、部署和清理属于不同操作，执行范围以用户当前授权为准。路径、日期和保留期示例不能覆盖服务器现有约定。

技能要求备份与验证，但不承诺所有部署都能零停机或自动恢复。配置检查成功不等于所有业务路由正常，回调地址可达也不等于支付已经完成。

## 验证

```bash
bash -n scripts/inspect.sh
python3 -m unittest discover -s tests -v
```

行为验证案例用于说明预期，不代表完整基准测试，也不意味着适配所有助手宿主。

## 参与贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。示例使用虚构环境，并保持只读检查与授权变更的边界清晰。

## 许可证

[MIT](LICENSE)。
