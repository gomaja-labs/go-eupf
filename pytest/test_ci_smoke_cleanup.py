"""Exercise the smoke script's EXIT trap at each background-start boundary."""
import os
from pathlib import Path
import signal
import subprocess
import time

import pytest


@pytest.mark.parametrize("boundary", ["capture", "app"])
def test_smoke_cleanup_bounds_background_start_failure(tmp_path, boundary):
    original = Path(__file__).resolve().parents[1] / "scripts/ci/check.sh"
    # Relocate the CI checkout and inject a failure immediately after the
    # background launch. All process management remains the shipping script's.
    script = original.read_text().replace("/src", str(tmp_path))
    fault = "false"
    if boundary == "app":
        fault = 'while [[ ! -e "$SMOKE_TEST_APP_READY" ]]; do sleep .01; done; false'
    script = script.replace(f"{boundary}_pid=$!", f"{boundary}_pid=$!\n\t\t{fault}")
    (tmp_path / "check.sh").write_text(script)
    commands = tmp_path / "commands"
    commands.mkdir()
    (tmp_path / "bin").mkdir()
    fixtures = {
        "go": "exit 0\n",
        "sudo": '''case "$1" in
mount|chown) exit 0 ;;
tcpdump) sleep .2 ;;
esac
exec "$@"
''',
        "tcpdump": '''echo "$$" >> "$SMOKE_TEST_PIDS"
echo 'listening on lo'
trap 'exit 0' TERM
while :; do sleep 1; done
''',
    }
    for name, body in fixtures.items():
        path = commands / name
        path.write_text("#!/bin/bash\n" + body)
        path.chmod(0o755)
    application = tmp_path / "bin/eupf"
    application.write_text('''#!/bin/bash
echo "$$" >> "$SMOKE_TEST_PIDS"
trap '' TERM
touch "$SMOKE_TEST_APP_READY"
while :; do sleep 1; done
''')
    application.chmod(0o755)
    pids = tmp_path / "pids"
    started = time.monotonic()
    process = subprocess.Popen(
        ["bash", str(tmp_path / "check.sh"), "smoke"],
        env={**os.environ, "PATH": f"{commands}:{os.environ['PATH']}",
             "SMOKE_TEST_PIDS": str(pids),
             "SMOKE_TEST_APP_READY": str(tmp_path / "app-ready")},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=10)
        assert process.returncode != 0, output.decode()
        if boundary == "app":
            assert b"eUPF did not stop within 5 seconds; sending SIGKILL" in output
        else:
            assert b"did not stop" not in output
        assert time.monotonic() - started < 9, output.decode()
        if pids.exists():
            for value in pids.read_text().split():
                with pytest.raises(ProcessLookupError):
                    os.kill(int(value), 0)
    finally:
        # On the broken implementation, remove the deliberately stuck children
        # after the outer test bound has proved the missing cleanup bound.
        if pids.exists():
            for value in pids.read_text().split():
                try:
                    os.kill(int(value), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
