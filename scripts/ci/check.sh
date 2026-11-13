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
	(cd scripts/enb-load-test/enb-emulator && go build ./... && go test ./... -count=1 && go vet ./...)
	status=0
	go test -exec sudo ./... -count=1 || status=1
	go test -exec sudo -race -count=1 ./cmd/core/... ./cmd/api/... ./cmd/config/... || status=1
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
	cleanup() {
		if [[ -n "$app_pid" ]]; then
			sudo kill -TERM "$app_pid" 2>/dev/null || true
			wait "$app_pid" || true
			app_pid=
		fi
		if [[ -n "$capture_pid" ]]; then
			sudo kill -INT "$capture_pid" 2>/dev/null || true
			wait "$capture_pid" || true
			capture_pid=
		fi
	}
	# eUPF and pytest run as root; give their output (captures, trace dumps,
	# pytest caches) back to the build user so the checkout stays removable.
	trap 'cleanup; sudo chown -R "$(id -u):$(id -g)" /src' EXIT
	for ueip in false true; do
		sudo tcpdump -U --immediate-mode -i lo -w "ci-results/pfcp-$ueip.pcap" udp port 8805 >"ci-results/capture-$ueip.log" 2>&1 &
		capture_pid=$!
		for _ in {1..100}; do
			if grep -q 'listening on lo' "ci-results/capture-$ueip.log"; then break; fi
			sleep .1
		done
		grep -q 'listening on lo' "ci-results/capture-$ueip.log"
		sudo env UPF_MAX_SESSIONS=1024 UPF_RESOURCE_REUSE_DELAY=1 UPF_FEATURE_UEIP="$ueip" ./bin/eupf >"ci-results/eupf-$ueip.log" 2>&1 &
		app_pid=$!
		python3 - <<'PY'
import socket, time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', 8080), timeout=.2):
            break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('eUPF did not become ready')
time.sleep(1)  # Wait for the fixture's one-second restoration window.
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
		# during teardown. Bound the complete suite without cutting those waits.
		timeout 300 sudo env EUPF_REGRESSION_BINARY="/src/bin/$binary" \
			EUPF_REGRESSION_EVIDENCE="/src/ci-results/$binary-regressions" \
			/opt/py/bin/pytest -v ./pytest/test_pfcp_regressions.py ./pytest/test_pfcp_transport.py
	done
	;;
*)
	echo 'usage: check.sh test|lint|smoke' >&2
	exit 2
	;;
esac
