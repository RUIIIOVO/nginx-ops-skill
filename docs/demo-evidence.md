# Demo evidence and redaction / 演示取证与脱敏

## Sources / 来源

The before view is derived from saved backup metadata: a runtime-directory manifest and a separate active-log manifest. The after view is derived from a later read-only filesystem inspection and `nginx -t`. Snapshot times are recorded in [evidence.json](../assets/evidence.json). Original manifests remain private because they include real deployment identifiers.

清理前视图来自已保存的运行目录清单及另一时点的活跃日志清单；清理后来自后续只读文件系统检查与 `nginx -t`。快照时间见 [evidence.json](../assets/evidence.json)。原清单含真实部署标识，未随仓库公开。

Only the measurements shown in the reports are claimed. The live root-file count, certificate-pair count, active log size, and check exit code were read from the inspected environment. The directory tree is an abbreviated view with the base path removed.

报告仅对展示的测量值负责：根目录文件数、证书对数量、活跃日志大小和检查退出码来自实际环境。目录树是移除基础路径后的节选。

## What the images are / 截图性质

Native desktop screenshot capture was unavailable in the capture environment. The images therefore show a browser-rendered terminal-style view of output produced by:

截图环境无法录制原生桌面窗口，因此图片使用浏览器渲染以下命令的实际输出：

```bash
python3 scripts/show_evidence.py before
python3 scripts/show_evidence.py after
```

These commands print the saved, redacted reports; they do not reconnect to a server, recreate its former state, or re-run an optimization. The images are not presented as original historical terminal screenshots.

这些命令只显示已保存的脱敏报告，不连接服务器、不重建历史状态，也不重新执行优化。图片不冒充历史终端原屏。

## Redaction / 脱敏方式

- Host addresses, SSH aliases, login identifiers, personal paths, private domains, business filenames, and certificate names are excluded from the public reports.
- Identifying values are removed before HTML rendering; the visible mosaic contains no original characters underneath it.
- Screenshots are flattened PNG files with image metadata removed. The repository contains no hidden unredacted image layers or original capture HTML.
- Runtime configuration, certificate/key contents, environment variables, account state, request bodies, and access-log lines are not included.

- 主机地址、SSH 别名、登录身份、个人路径、私有域名、业务文件名及证书名称不进入公开报告。
- 身份信息在 HTML 渲染前已删除；可见马赛克下方没有原始字符。
- 图片为扁平 PNG，并移除图像元数据；仓库不包含隐藏原图图层或原始渲染 HTML。
- 不公开运行配置正文、证书/密钥内容、环境变量、账户状态、请求体或访问日志行。

## Interpretation / 结果解读

The active access log changed from roughly 3.83 GiB to 9.94 MiB at capture time because rotation separates new writes from historical data. This is not a claim that historical logs were deleted, that total disk use fell by that amount, or that future active logs will remain at that size. Counts and sizes are specific to this recorded example.

活跃访问日志从约 3.83 GiB 变为采集时的 9.94 MiB，是轮转将新写入与历史日志分离的结果；不代表删除历史、释放同等磁盘空间，或保证以后一直维持这个大小。数量和大小仅对应本次示例。
