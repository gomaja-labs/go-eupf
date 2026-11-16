#!/usr/bin/env bash
# Start the runtime image with its documented capabilities and require HTTP
# readiness and buffered-forwarding initialization.
set -euo pipefail
image=${1:-eupf:scan}
output=${EUPF_RUNTIME_SMOKE_OUTPUT:-ci-results/runtime-readiness}
mkdir -p "$output"
application=
cleanup() {
	code=$?
	if [[ -n "$application" ]]; then
		docker logs "$application" >"$output/application.log" 2>&1 || true
		docker inspect "$application" >"$output/application.json" || true
		docker rm -f "$application" >/dev/null || true
	fi
	if ((code != 0)) && [[ -f "$output/application.log" ]]; then tail -n 80 "$output/application.log" >&2; fi
	exit "$code"
}
trap cleanup EXIT
user_options=()
if [[ -n "${EUPF_RUNTIME_SMOKE_USER:-}" ]]; then user_options=(--user "$EUPF_RUNTIME_SMOKE_USER"); fi
uid=$(docker run --rm "${user_options[@]}" --entrypoint id "$image" -u)
application=$(docker create "${user_options[@]}" --cap-drop ALL \
	--cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_RESOURCE \
	--cap-add BPF --cap-add PERFMON \
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
# The default runtime supplies read-only sysfs and no mounted BPF filesystem.
docker exec "$application" awk '
    $3 == "bpf" { bpf = 1 }
    $2 == "/sys" { sysfs = 1 }
    $2 ~ /^\/sys(\/|$)/ && $4 !~ /(^|,)ro(,|$)/ { writable = 1 }
    END { exit (!sysfs || writable || bpf) }
' /proc/mounts
running_uid=$(docker exec "$application" id -u)
[[ "$running_uid" == "$uid" ]]
# Buffering opens its raw packet socket, creates the private eub*/eup* veth
# pair and attaches its TC filter after readiness. A failed step removes the
# pair and logs the error, so require the pair to persist with no failure.
failure='Buffered forwarding initialization failed'
stable=0
for ((attempt = 0; attempt < 120 && stable < 4; attempt++)); do
	if docker logs "$application" 2>&1 | grep -qF "$failure"; then
		printf '%s\n' "$failure" >&2
		exit 1
	fi
	if docker exec "$application" ls /sys/class/net | grep -q '^eub'; then
		stable=$((stable + 1))
	else
		stable=0
	fi
	sleep .5
done
if ((stable < 4)); then
	printf 'Buffered forwarding was not initialized\n' >&2
	exit 1
fi
printf 'Runtime API and buffered forwarding ready; uid=%s image=%s\n' "$uid" "$image"
