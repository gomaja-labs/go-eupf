#!/usr/bin/env bash
# Run inside the Dockerfile development stage, as the build user.
set -euo pipefail
cd /src
case "${1:-}" in
test)
	sudo mount -t bpf bpf /sys/fs/bpf
	go generate ./cmd/...
	go build ./...
	go vet ./...
	/opt/py/bin/pytest -q ./pytest/test_ci_smoke_cleanup.py
	(cd scripts/enb-load-test/enb-emulator && go build ./... && go test ./... -count=1 && go vet ./...)
	# The complete verifier-backed suite measured 589 seconds; race coverage
	# reached the old ten-minute guard. Twenty minutes leaves another full
	# measured run of headroom while retaining a per-package hang bound.
	status=0
	go test -exec sudo ./... -count=1 -timeout=20m || status=1
	go test -exec sudo -race -count=1 -timeout=20m ./cmd/core/... ./cmd/api/... ./cmd/config/... || status=1
	exit "$status"
	;;
lint)
	go tool actionlint
	go generate ./cmd/...
	git diff --exit-code
	go mod tidy -diff
	(cd scripts/enb-load-test/enb-emulator && go mod tidy -diff)
	go tool staticcheck ./...
	(cd scripts/enb-load-test/enb-emulator && go vet ./... && golangci-lint run ./...)
	golangci-lint run ./...
	;;
smoke)
	sudo mount -t bpf bpf /sys/fs/bpf
	sudo mount -t debugfs debugfs /sys/kernel/debug
	go generate ./cmd/...
	go build -o bin/eupf ./cmd
	mkdir -p ci-results
	app_pid= capture_pid=
	stop_background() {
		local name=$1 pid=$2 grace=$3 deadline status=0
		# setsid isolates the command and sudo's child. TERM is not inherited
		# as ignored by a background job, unlike INT in non-interactive bash.
		# Signal both the group and leader: sudo can lose a forwarded signal
		# between fork and exec (https://github.com/sudo-project/sudo/issues/566).
		sudo kill -TERM -- "-$pid" "$pid" 2>/dev/null || true
		deadline=$((SECONDS + grace))
		while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep .1; done
		if kill -0 "$pid" 2>/dev/null; then
			echo "$name did not stop within $grace seconds; sending SIGKILL" >&2
			status=1
			sudo kill -KILL -- "-$pid" "$pid" 2>/dev/null || true
			deadline=$((SECONDS + 2))
			while kill -0 "$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep .1; done
		fi
		if kill -0 "$pid" 2>/dev/null; then
			echo "$name did not exit after SIGKILL" >&2
			return 1
		fi
		# Reap only after it has exited: no wait can hold the EXIT trap open.
		wait "$pid" || true
		return "$status"
	}
	cleanup() {
		local status=0
		if [[ -n "$app_pid" ]]; then
			# The default PFCP delivery and graceful-release window is 32 s.
			stop_background eUPF "$app_pid" 40 || status=1
			app_pid=
		fi
		if [[ -n "$capture_pid" ]]; then
			stop_background tcpdump "$capture_pid" 5 || status=1
			capture_pid=
		fi
		return "$status"
	}
	# eUPF and pytest run as root; give their output (captures, trace dumps,
	# pytest caches) back to the build user so the checkout stays removable.
	trap 'status=$?; cleanup || status=1; sudo chown -R "$(id -u):$(id -g)" /src; exit "$status"' EXIT
	trap 'exit 143' TERM
	trap 'exit 130' INT
	for ueip in false true; do
		# Truncate in the foreground; only this launch can satisfy readiness.
		: >"ci-results/capture-$ueip.log"
		setsid sudo tcpdump -U --immediate-mode -i lo -w "ci-results/pfcp-$ueip.pcap" udp port 8805 >>"ci-results/capture-$ueip.log" 2>&1 &
		capture_pid=$!
		for _ in {1..100}; do
			if grep -q 'listening on lo' "ci-results/capture-$ueip.log"; then break; fi
			kill -0 "$capture_pid"
			sleep .1
		done
		grep -q 'listening on lo' "ci-results/capture-$ueip.log"
		setsid sudo env UPF_MAX_SESSIONS=1024 UPF_RESTORATION_PERIOD=1 UPF_FEATURE_UEIP="$ueip" ./bin/eupf >"ci-results/eupf-$ueip.log" 2>&1 &
		app_pid=$!
		python3 - "$ueip" <<'PY'
import socket, sys, time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', 8080), timeout=.2):
            break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('eUPF did not become ready')
if sys.argv[1] == 'true':
    time.sleep(1)  # Automatic UE IPv4 allocation waits for restoration.
PY
		if [[ "$ueip" == false ]]; then
			timeout 90 sudo /opt/py/bin/pytest -v -k 'not test_create_session_ueip' ./pytest/test_session.py
		else
			timeout 90 sudo /opt/py/bin/pytest -v ./pytest/test_session.py::test_create_association ./pytest/test_session.py::test_create_session_ueip
		fi
		cleanup
	done
	go build -o bin/mapfault ./cmd/core/testtools/mapfault
	go build -race -o bin/eupf-race ./cmd
	for binary in eupf eupf-race; do
		# Each process exercises the restoration hold; race binaries also wait
		# during teardown. The race suite measured 295 seconds on an idle host;
		# allow a 100% margin for shared GitHub runners.
		timeout --kill-after=10 600 sudo env EUPF_REGRESSION_BINARY="/src/bin/$binary" \
			EUPF_REGRESSION_EVIDENCE="/src/ci-results/$binary-regressions" \
			/opt/py/bin/pytest -v ./pytest/test_pfcp_regressions.py ./pytest/test_pfcp_transport.py
	done
	;;
*)
	echo 'usage: check.sh test|lint|smoke' >&2
	exit 2
	;;
esac
