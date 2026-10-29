# Contributing

Contributions that improve inspection accuracy, change verification, and recovery guidance are welcome.

- Use fictional hosts and reserved example domains such as `example.com`.
- Do not include production configurations, credentials, private keys, personal paths, access logs, or unsanitized screenshots.
- Keep examples portable. Document version requirements instead of assuming a recent Nginx, Docker, Python, curl, or logrotate.
- Preserve the difference between read-only inspection and authorized changes.
- Update both README languages when changing user-facing behavior.
- Describe what was checked and any limitations. Do not claim zero downtime or universal recovery from a syntax check alone.

Before proposing a change:

```bash
bash -n scripts/inspect.sh
```

Do not run checks against someone else's server as part of a contribution.

# 参与贡献

欢迎改进盘点准确性、变更验证和恢复说明。

- 使用虚构主机与 `example.com` 等保留示例域名。
- 不提交生产配置、凭据、私钥、个人路径、访问日志或未脱敏截图。
- 说明版本要求，不默认所有服务器都有新版工具。
- 保持只读与授权变更边界；涉及对外说明时同步两版 README。
- 说明实际验证和局限，不以语法检查推导零停机或万能恢复。

提交前运行上面的本地语法检查；未经授权，不要对他人的服务器执行检查或操作。
