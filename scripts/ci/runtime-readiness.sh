#!/usr/bin/env bash
# Start the runtime image with its documented capabilities and require HTTP readiness.
set -euo pipefail
image=${1:-eupf:scan}
output=${EUPF_RUNTIME_SMOKE_OUTPUT:-ci-results/runtime-readiness}
mkdir -p "$output"
application=
mountpoint=
mounted=0
cleanup() {
	code=$?
	if [[ -n "$application" ]]; then
		docker logs "$application" >"$output/application.log" 2>&1 || true
		docker inspect "$application" >"$output/application.json" || true
		docker rm -f "$application" >/dev/null || true
	fi
	if [[ "$mounted" == 1 ]]; then
		if ! sudo -n umount "$mountpoint"; then code=1; fi
	fi
	if [[ -n "$mountpoint" ]]; then rmdir "$mountpoint" || code=1; fi
	if ((code != 0)) && [[ -f "$output/application.log" ]]; then tail -n 80 "$output/application.log" >&2; fi
	exit "$code"
}
trap cleanup EXIT
user_options=()
if [[ -n "${EUPF_RUNTIME_SMOKE_USER:-}" ]]; then user_options=(--user "$EUPF_RUNTIME_SMOKE_USER"); fi
uid=$(docker run --rm "${user_options[@]}" --entrypoint id "$image" -u)
# Give this run its own bpffs. Programs and interfaces are created only in the
# application's container; this host mount contains only this run's map pins.
mountpoint=$(mktemp -d)
sudo -n mount -t bpf bpf "$mountpoint"
mounted=1
application=$(docker create "${user_options[@]}" --cap-drop ALL \
	--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_RESOURCE \
	--cap-add BPF --cap-add PERFMON --cap-add DAC_OVERRIDE \
	--mount "type=bind,src=$mountpoint,dst=/sys/fs/bpf" \
	-p 127.0.0.1::8080 -e UPF_API_ADDRESS=:8080 -e UPF_API_TOKEN=runtime-smoke \
	-e UPF_MAX_SESSIONS=1024 -e UPF_PFCP_REPLAY_MEMORY_MIB=96 \
	-e UPF_XDP_ATTACH_MODE=generic -e UPF_INTERFACE_NAME=lo "$image")
docker start "$application" >/dev/null
port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$application")
python3 - "$port" <<'PY'
import sys,time,urllib.request
url=f'http://127.0.0.1:{sys.argv[1]}/api/v1/health'
last=None
for _ in range(300):
 try:
  with urllib.request.urlopen(url,timeout=.2)as response:
   if response.status==200:break
 except OSError as error:last=error
 time.sleep(.2)
else:raise SystemExit(f'Runtime API did not become ready: {last}')
PY
running_uid=$(docker exec "$application" id -u)
[[ "$running_uid" == "$uid" ]]
printf 'Runtime API ready; uid=%s image=%s\n' "$uid" "$image"
