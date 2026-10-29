# 环境盘点与结构优化

## 先定位，再设计

1. 确认用户指定SSH目标及登录方式；使用已有别名，不猜root、密钥或服务路径。
2. 原生部署：进程启动参数、systemd unit、nginx-V编译路径和nginx-T的include。容器部署：镜像ID、命令、端口、指定挂载字段，避免完整inspect环境输出到聊天。
3. 提取每个server的listen/server_name/TLS/root/alias/proxy_pass/try_files；理清默认站点、共享map/geo及include顺序。
4. 核对静态文件实际存在、软链接关系和公共目录包含关系。
5. 查证书管理、logrotate、cron/systemd timers、备份和发布脚本；关联用户本地项目。线上变化要防止被旧部署源覆盖。
6. 核对Python、Nginx、Docker、Compose、logrotate、curl版本，基于实际能力实现。

只读盘点不要顺手nginx-s reload、reconcile或logrotate-f；nginx-t虽不改配置，可能尝试打开日志，若用户限制严格则说明或采用隔离检查。

## 推荐职责（不是强制路径）

```text
<服务父目录>/
├── nginx/                  当前配置、程序、当前证书、必要站点文件
│   ├── nginx.conf
│   ├── conf.d/
│   ├── html/<应用>/
│   ├── cert/<证书组>/
│   ├── ssl/                登记、候选、事务（若现有系统采用）
│   ├── scripts/
│   └── docs/
├── nginx-logs/             活跃日志
├── nginx-backups/          永久/策略保留的恢复点
│   ├── full/
│   ├── config/
│   ├── cert/
│   ├── html/
│   └── logs/
├── nginx-archive/          一次性历史遗留
└── nginx-work/             候选、解包、未完成事务、验证输出
```

实际可能采用/etc/nginx、/var/log/nginx、/srv/www等系统约定；保留已合理的路径，目录优化不是全部迁移到这个例子。独立项目静态根不在Nginx目录中也可以合理，只需明确挂载、备份和发布入口。

历史目录和备份不应位于公开root之下。多个域名共享同一应用可以共享一份静态构建；不同应用的公开根不要互相包含。配置按域名拆开是可读性改进，不能自动隔离磁盘或代理路径。

## 优化优先级

先处理已证实的文件跨站暴露、证书/密钥一致性、发布删除风险和真实路由故障，再处理目录命名与去重。保留不同站点的TLS、超时、上传限制、WebSocket/SSE参数，避免万能模板引入回归。

默认站点行为单独审查：include排序可能改变未匹配Host、无SNI和TLS协议默认值。明确拒绝未知请求可以是合适目标，但需用户授权并验证现有域名，不因为拆文件自动改变安全策略。

## 判断错配

请求示例：域名A/应用B/index.html。

- 正文确实是B：核对A的root是否包含B，或alias/proxy是否交叉，修根边界。
- 正文与A首页相同：SPA兜底，不能直接判B暴露。
- 状态200但JS返回HTML：缺失资源误兜底，按静态扩展名/资源目录严格404，页面路由仍可SPA回退。
- 301：核对Location、Host、路径及查询参数，避免支付/API跨域跳转。
- TLS证书与Host：分别验证SNI选择和HTTP虚拟主机匹配。

根因已解决时不再添加针对历史路径的黑名单，除非另有明确路径拒绝需求。
