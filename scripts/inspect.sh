#!/usr/bin/env bash
# 只读盘点：不执行备份、签发、轮转、reload，不打印环境变量/密钥。
set -euo pipefail
ssh_target=''
container=''
usage() {
  printf '用法: bash %s --ssh SSH别名 [--container Nginx容器名]\n' "$0"
}
while (( $# )); do
  case "$1" in
    --ssh|--container)
      if (( $# < 2 )); then usage >&2; exit 2; fi
      if [[ "$1" == --ssh ]]; then ssh_target=$2; else container=$2; fi
      shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ ! "$ssh_target" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  printf '请指定已有 SSH 别名，不传 shell 命令或连接选项。\n' >&2
  exit 2
fi
if [[ -n "$container" && ! "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  printf '无效容器名。\n' >&2
  exit 2
fi
# 参数经过字符白名单，无任意远程 shell 代码；不假设路径或登录用户。
ssh -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes "$ssh_target" "bash -s -- '$container'" <<'REMOTE'
set -u
container=$1
printf 'Observation time: '
date -Is
printf '\nIdentity: '
id
printf '\nPlatform:\n'
uname -srm
printf '\nNginx processes:\n'
ps -eo pid,ppid,user,args | awk '/nginx: master process|nginx: worker process/ && !/awk/'
printf '\nTool availability:\n'
for program in nginx docker docker-compose logrotate python3 systemctl; do
  command -v "$program" || true
done
printf '\nRoot filesystem:\n'
df -h /
if [[ -n "$container" ]]; then
  printf '\nSpecified container structure (no environment):\n'
  docker inspect "$container" --format 'image={{.Config.Image}} pid={{.State.Pid}} mounts={{json .Mounts}} ports={{json .HostConfig.PortBindings}}'
  printf '\nContainer Nginx version/config paths:\n'
  docker exec "$container" nginx -V 2>&1
else
  if command -v nginx >/dev/null 2>&1; then
    printf '\nNative Nginx version/config paths:\n'
    nginx -V 2>&1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    printf '\nNative service identity:\n'
    systemctl show nginx --property=LoadState --property=ActiveState --property=FragmentPath --no-pager 2>/dev/null || true
  fi
fi
printf '\nAvailable rotation version:\n'
if command -v logrotate >/dev/null 2>&1; then logrotate --version 2>&1; fi
printf '\nRead actual config, schedules, and project paths next; this script does not infer them.\n'
REMOTE
