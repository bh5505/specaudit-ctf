"""Exercise the optional target with the real curl adapter and prove teardown."""
from __future__ import annotations

import hashlib
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import pytest

from exercise.local_target import TargetError, target
from extension.contract import Extension
from extension.dispatch import dispatch_invoke


def test_real_http_target_dispatch_ignores_ambient_config_and_restores_environment(tmp_path, monkeypatch):
    if os.name != 'posix' or not Path('/usr/bin/curl').is_file():
        pytest.skip('real optional HTTP scenario requires /usr/bin/curl on POSIX')
    monkeypatch.setenv('PATH', '/usr/bin:/bin')
    config = tmp_path / 'ambient'
    config.mkdir()
    (config / '.curlrc').write_text('proxy = "http://127.0.0.1:1"\n')
    monkeypatch.setenv('CURL_HOME', str(config))
    monkeypatch.setenv('ALL_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROBE_DISPATCH_SCOPE', 'previous-scope')
    artifacts = tmp_path / 'artifacts'
    artifacts.mkdir(mode=0o700)
    with target() as (arm, action, args, metadata):
        outcome = dispatch_invoke(Extension(), arm_id=arm, action=action, args=args,
                                  attempt_id='attempt-' + 'a' * 64, artifact_dir=str(artifacts))
        assert outcome.exit_code == 0 and outcome.envelope['status'] == 'complete'
        assert args['url'].startswith('http://127.0.0.1:')
        report = json.loads(next(artifacts.iterdir()).read_text())
        observed = json.loads(report['output'])
        assert observed['status'] == 200
        assert hashlib.sha256(observed['body_head'].encode()).hexdigest() == metadata['body_sha256']
        assert metadata['requests'] == [{'method': 'GET', 'path': '/ctf/status', 'status': 200}]
    assert metadata['cleanup'] == 'stopped'
    assert os.environ['CURL_HOME'] == str(config)
    assert os.environ['ALL_PROXY'] == 'http://127.0.0.1:1'
    assert os.environ['HTTP_PROBE_DISPATCH_SCOPE'] == 'previous-scope'
    with pytest.raises(OSError):
        socket.create_connection(('127.0.0.1', urlparse(args['url']).port), timeout=0.2)


def test_target_cleanup_also_runs_when_dispatch_raises(tmp_path, monkeypatch):
    if os.name != 'posix' or not Path('/usr/bin/curl').is_file():
        pytest.skip('optional HTTP scenario requires curl on POSIX')
    monkeypatch.setenv('PATH', '/usr/bin:/bin')
    monkeypatch.setenv('HTTP_PROBE_DISPATCH_SCOPE', 'retained-scope')
    with pytest.raises(RuntimeError, match='interrupted step'):
        with target() as (_, _, args, metadata):
            raise RuntimeError('interrupted step')
    assert metadata['cleanup'] == 'stopped'
    assert os.environ['HTTP_PROBE_DISPATCH_SCOPE'] == 'retained-scope'
    with pytest.raises(OSError):
        socket.create_connection(('127.0.0.1', urlparse(args['url']).port), timeout=0.2)


def test_target_refuses_missing_dependency(monkeypatch):
    monkeypatch.setenv('PATH', '')
    with pytest.raises(TargetError, match='installed curl'):
        with target():
            pytest.fail('target must not start without curl')
