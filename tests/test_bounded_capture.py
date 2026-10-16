"""Subprocess output must be bounded before it is accumulated or parsed."""

import os
import subprocess
import sys
import time

import pytest

from extension.arms.bounded_capture import run_bounded


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_combined_output_cap_and_stdin_delivery():
    cmd = [sys.executable, "-c", "import sys; print(sys.stdin.read(), end=''); sys.stderr.write('x'*500000)"]
    proc, overflowed = run_bounded(cmd, 5, 4096, input="host.example\n")
    assert overflowed
    assert len(proc.stdout.encode()) + len(proc.stderr.encode()) <= 4096
    received, overflowed = run_bounded(
        [sys.executable, "-c", "import sys; print(sys.stdin.read(), end='')"],
        5, 4096, input="host.example\n",
    )
    assert not overflowed and received.stdout == "host.example\n"


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_pipe_inheriting_descendant_cannot_extend_timeout():
    script = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],"
        "stdout=sys.stdout,stderr=sys.stderr)"
    )
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded([sys.executable, "-c", script], 0.4, 4096)
    assert time.monotonic() - start < 3


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_blocked_stdin_writer_cannot_extend_timeout():
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            0.4, 200_000, input="x" * 100_000,
        )
    assert time.monotonic() - start < 3


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_parent_success_cleans_descendant_that_closed_pipes(tmp_path):
    marker = tmp_path / "survived"
    child = (
        "import pathlib,sys,time; time.sleep(0.6); "
        "pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]], "
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
    )
    proc, overflowed = run_bounded(
        [sys.executable, "-c", parent, child, str(marker)], 3, 4096,
    )
    assert proc.returncode == 0 and not overflowed
    time.sleep(0.8)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_file_capture_caps_disk_and_stderr(tmp_path):
    path = tmp_path / "capture"
    with path.open("wb") as output:
        proc, overflowed = run_bounded(
            [sys.executable, "-c", "import sys;sys.stdout.write('z'*1000000)"],
            5, 1024, stdout_file=output, stderr_maximum=128,
        )
    assert overflowed
    assert path.stat().st_size <= 1024
    assert proc.stdout == ""


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_file_write_failure_is_not_success():
    class FullDisk:
        def write(self, data):
            raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        run_bounded(
            [sys.executable, "-c", "print('evidence')"], 5, 1024,
            stdout_file=FullDisk(),
        )


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_file_short_write_is_not_success():
    class PartialDisk:
        def write(self, data):
            return 0

    with pytest.raises(OSError, match="short write"):
        run_bounded(
            [sys.executable, "-c", "print('evidence')"], 5, 1024,
            stdout_file=PartialDisk(),
        )


@pytest.mark.skipif(os.name != "posix", reason="process-group capture is POSIX-only")
def test_closed_output_file_is_not_success(tmp_path):
    path = tmp_path / "closed"
    output = path.open("wb")
    output.close()
    with pytest.raises(OSError, match="output file write failed"):
        run_bounded(
            [sys.executable, "-c", "print('evidence')"], 5, 1024,
            stdout_file=output,
        )
