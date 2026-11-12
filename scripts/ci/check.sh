#!/usr/bin/env bash
# Run inside the Dockerfile development stage, as the build user.
set -euo pipefail
cd /src
case "${1:-}" in
test)
	sudo mount -t bpf bpf /sys/fs/bpf
	# Redirect assertions need a resolved FIB neighbor. Keep their synthetic
	# destinations on a private link instead of depending on Docker gateway ARP.
	sudo ip link add ci-egress type veth peer name ci-peer
	sudo ip link set ci-egress up
	sudo ip link set ci-peer up
	sudo ip route add 10.3.0.0/24 dev ci-egress
	sudo ip route add 1.1.1.1/32 dev ci-egress
	sudo ip route add 1.0.0.0/32 dev ci-egress
	sudo ip route add 0.0.0.0/32 dev ci-egress
	for destination in 10.3.0.10 10.3.0.20 1.1.1.1 1.0.0.0 0.0.0.0; do
		sudo ip neigh add "$destination" lladdr 02:00:00:00:00:02 nud permanent dev ci-egress
	done
	go generate ./cmd/...
	go build ./...
	go vet ./...
	go test -exec sudo ./... -count=1
	go test -exec sudo -race -count=1 ./cmd/core/... ./cmd/api/... ./cmd/config/...
	(cd scripts/enb-load-test/enb-emulator && go build ./... && go test ./... -count=1 && go vet ./...)
	;;
lint)
	go tool actionlint
	go generate ./cmd/...
	go generate cli/eupf/injection/wire.go
	git diff --exit-code
	go mod tidy -diff
	(cd scripts/enb-load-test/enb-emulator && go mod tidy -diff)
	go tool staticcheck ./...
	golangci-lint run ./...
	(cd scripts/enb-load-test/enb-emulator && go vet ./... && golangci-lint run ./...)
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
	trap cleanup EXIT
	for ueip in false true; do
		sudo tcpdump -U --immediate-mode -i lo -w "ci-results/pfcp-$ueip.pcap" udp port 8805 >"ci-results/capture-$ueip.log" 2>&1 &
		capture_pid=$!
		for _ in {1..100}; do
			if grep -q 'listening on lo' "ci-results/capture-$ueip.log"; then break; fi
			sleep .1
		done
		grep -q 'listening on lo' "ci-results/capture-$ueip.log"
		sudo env UPF_MAX_SESSIONS=1024 UPF_FEATURE_UEIP="$ueip" ./bin/eupf >"ci-results/eupf-$ueip.log" 2>&1 &
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
PY
		if [[ "$ueip" == false ]]; then
			timeout 90 sudo /opt/py/bin/pytest -v -k 'not test_create_session_ueip' ./pytest/test_session.py
		else
			timeout 90 sudo /opt/py/bin/pytest -v ./pytest/test_session.py::test_create_association ./pytest/test_session.py::test_create_session_ueip
		fi
		cleanup
	done
	;;
*)
	echo 'usage: check.sh test|lint|smoke' >&2
	exit 2
	;;
esac
