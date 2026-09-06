import types

import pytest

from tests.test_plugin_runtime import _load_plugin


@pytest.fixture
def database(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    names = {0x1000: 'original', 0x2000: 'other'}
    comments = {}
    calls = []
    plugin.ida_bytes.is_mapped = lambda ea: 0x1000 <= ea < 0x3000
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea) if ea in names else None
    plugin.ida_name.SN_NOWARN = 1
    plugin.ida_name.VNT_IDENT = 0
    plugin.ida_name.validate_name = lambda name, kind: name if name.isidentifier() else ''
    plugin.ida_name.get_name = lambda ea: names[ea]
    plugin.ida_name.get_name_ea = lambda bad, name: next((ea for ea, value in names.items() if value == name), bad)

    def rename(ea, name, flags):
        calls.append(('rename', ea, name))
        names[ea] = name
        return True

    def comment(ea, value, repeatable):
        calls.append(('comment', ea, value))
        comments[ea, repeatable] = value
        return True

    plugin.ida_name.set_name = rename
    plugin.idc.get_cmt = plugin.idc.get_func_cmt = lambda ea, repeat: comments.get((ea, repeat), '')
    plugin.idc.set_cmt = plugin.idc.set_func_cmt = comment
    plugin.idc.PT_TYP, plugin.idc.PT_FILE = 1, 2
    return plugin, names, comments, calls


RENAME = {'op': 'rename-func', 'ea': '0x1000', 'name': 'renamed'}
COMMENT = {'op': 'comment', 'ea': '0x1001', 'comment': 'changed'}


@pytest.mark.parametrize('invalid', [None, [], {'op': 'missing'}, dict(RENAME, ea=True),
    dict(RENAME, ea='0x9999'), dict(RENAME, name='other'), dict(RENAME, name='bad name'),
    dict(COMMENT, repeatable=1), dict(COMMENT, unexpected=True),
    {'op': 'create-struct', 'definition': 'struct X {int a;};'}])
def test_invalid_last_operation_leaves_database_untouched(database, invalid):
    plugin, names, _, calls = database
    result = plugin.execute_batch([RENAME, invalid])
    assert result['phase'] == 'validation'
    assert result['applied'] == 0
    assert calls == [] and names[0x1000] == 'original'


def test_preview_and_execution_revalidate(database):
    plugin, names, _, calls = database
    result = plugin.execute_batch([RENAME, COMMENT], dry_run=True)
    assert result['status'] == 'preview' and result['applied'] == 0
    assert calls == []
    names[0x2000] = 'renamed'
    assert plugin.execute_batch([RENAME])['phase'] == 'validation'
    assert calls == []


def test_false_result_rolls_back_comments_and_names_in_one_callback(database):
    plugin, names, comments, calls = database
    sync_calls = []
    def sync(callback, mode):
        sync_calls.append(mode)
        result = callback()
        assert result == 0
        return result
    plugin.ida_kernwin.execute_sync = sync
    original = plugin.idc.set_cmt
    plugin.idc.set_cmt = lambda ea, value, repeat: False if value == 'fail' else original(ea, value, repeat)
    result = plugin.execute_batch([RENAME, COMMENT, dict(COMMENT, comment='fail')])
    assert result['failed_at'] == 2 and result['rollback_complete'] is True
    assert result['state'] == 'restored_values'
    assert names[0x1000] == 'original' and comments[0x1001, False] == ''
    assert len(sync_calls) == 1
    assert len(result['rollback']) == 3


def test_mutate_then_raise_is_compensated(database):
    plugin, names, _, _ = database
    original = plugin.ida_name.set_name
    def rename(ea, name, flags):
        original(ea, name, flags)
        if name == 'renamed':
            raise RuntimeError('failure after write')
        return True
    plugin.ida_name.set_name = rename
    result = plugin.execute_batch([RENAME])
    assert result['rollback_complete'] is True and names[0x1000] == 'original'


def test_rollback_failure_is_not_counted_as_success(database):
    plugin, names, _, _ = database
    original = plugin.ida_name.set_name
    plugin.ida_name.set_name = lambda ea, name, flags: False if name == 'original' else original(ea, name, flags)
    plugin.idc.set_cmt = lambda *args: False
    result = plugin.execute_batch([RENAME, COMMENT])
    assert result['rollback_complete'] is False and result['state'] == 'inspect_required'
    assert result['rollback'][-1]['success'] is False
    assert names[0x1000] == 'renamed'
    assert result['rolled_back'] == 1  # Failed comment had no effect; name restoration failed.


def test_best_effort_stops_without_claiming_rollback(database):
    plugin, names, _, _ = database
    plugin.idc.parse_decls = lambda *args: 1
    result = plugin.execute_batch([RENAME, {'op': 'create-struct', 'definition': 'broken'}], mode='best_effort')
    assert result['failed_at'] == 1 and result['rollback_attempted'] is False
    assert result['state'] == 'inspect_required' and names[0x1000] == 'renamed'


@pytest.mark.parametrize('errors', [0, 2])
def test_c_parser_reports_error_count_and_receives_header_path(database, tmp_path, errors):
    plugin, _, _, _ = database
    calls = []
    def parse(source, flags):
        calls.append((source, flags))
        return errors
    plugin.idc.parse_decls = parse
    assert plugin.create_struct('struct X {int a;};')['success'] is (errors == 0)
    assert plugin.create_type_from_c('typedef int TestType;')['parse_errors'] == errors
    header = tmp_path / 'fixture.h'
    header.write_text('typedef int HeaderType;')
    plugin.ALLOWED_IMPORT_ROOTS = [str(tmp_path.resolve())]
    result = plugin.import_c_header(str(header))
    assert result['success'] is (errors == 0)
    assert calls[-1] == (str(header.resolve()), plugin.idc.PT_FILE | plugin.idc.PT_TYP)


def test_rejected_sync_does_not_masquerade_as_success(database):
    plugin, _, _, _ = database
    plugin.ida_kernwin.execute_sync = lambda *args: -1
    with pytest.raises(RuntimeError, match='rejected'):
        plugin.safe_write(lambda: True)


def test_batch_is_bounded(database):
    plugin, _, _, calls = database
    assert plugin.execute_batch([COMMENT] * 257)['phase'] == 'validation'
    assert calls == []
