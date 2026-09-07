from pathlib import Path
import time
from unittest.mock import Mock

import cli


def installed_pair(tmp_path):
    executable = tmp_path / 'ida.exe'
    executable.touch()
    directory = tmp_path / 'plugins'
    directory.mkdir()
    for name in ('ph4ntom_ida_bridge.py', 'api_schema.json'):
        (directory / name).write_text('original ' + name, encoding='utf-8')
    return executable, directory


def test_missing_schema_does_not_partially_replace_plugin(tmp_path, monkeypatch):
    executable, directory = installed_pair(tmp_path)
    monkeypatch.setattr(cli, 'SCHEMA_SOURCE', tmp_path / 'missing.json')
    assert cli.install_plugin(str(executable), force=True)['success'] is False
    assert (directory / 'ph4ntom_ida_bridge.py').read_text() == 'original ph4ntom_ida_bridge.py'
    assert not list(directory.glob('*.bak'))


def test_repeated_updates_preserve_previous_backups(tmp_path):
    executable, directory = installed_pair(tmp_path)
    backup = directory / 'ph4ntom_ida_bridge.py.bak'
    backup.write_text('earlier custom version')
    result = cli.install_plugin(str(executable), force=True)
    assert result['success']
    assert backup.read_text() == 'earlier custom version'
    saved = result['backups'][str(directory / 'ph4ntom_ida_bridge.py')]
    assert Path(saved).read_text() == 'original ph4ntom_ida_bridge.py'


def test_second_replacement_failure_restores_first(tmp_path, monkeypatch):
    executable, directory = installed_pair(tmp_path)
    real_replace = cli.os.replace
    def fail_schema(source, target):
        if Path(target).name == 'api_schema.json':
            raise PermissionError('injected locked schema')
        real_replace(source, target)
    monkeypatch.setattr(cli.os, 'replace', fail_schema)
    result = cli.install_plugin(str(executable), force=True)
    assert result['success'] is False and result['rollback_complete'] is True
    for name in ('ph4ntom_ida_bridge.py', 'api_schema.json'):
        assert (directory / name).read_text() == 'original ' + name


def test_invalid_explicit_ida_directory_does_not_use_other_installation(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.shutil, 'which', Mock(return_value='unrelated-ida.exe'))
    assert cli.find_ida(str(tmp_path / 'missing')) == ''


def test_wait_honors_short_deadline():
    client = Mock()
    client.ping.return_value = {'error': 'offline'}
    started = time.monotonic()
    assert cli._wait_for_bridge(client, 0.05)['success'] is False
    assert time.monotonic() - started < 0.3
    assert client.ping.call_args.kwargs['timeout'] <= 0.05
