"""Executed by IDA in run_ida.py's disposable database, never an existing IDB."""
import importlib.util
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_kernwin
import ida_name
import idautils
import idc


report = {'success': False, 'ida_version': ida_kernwin.get_kernel_version()}
try:
    if not Path(idc.get_input_file_path()).name.startswith('batch_fixture'):
        raise RuntimeError('Only the repository test fixture may be used')
    ida_auto.auto_wait()
    spec = importlib.util.spec_from_file_location('ph4ntom_fixture_plugin', os.environ['PH4NTOM_TEST_PLUGIN'])
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    ea = next(iter(idautils.Functions()))
    original = ida_name.get_name(ea)
    rename = {'op': 'rename-func', 'ea': hex(ea), 'name': 'ph4ntom_verified_fixture'}
    assert plugin.execute_batch([rename], dry_run=True)['status'] == 'preview'
    assert ida_name.get_name(ea) == original
    assert plugin.execute_batch([rename])['status'] == 'ok'
    before = idc.get_cmt(ea, False) or ''
    original_setter = plugin.idc.set_cmt

    def fail_marker(address, value, repeatable):
        return False if value == 'fixture_fail' else original_setter(address, value, repeatable)

    plugin.idc.set_cmt = fail_marker
    try:
        result = plugin.execute_batch([
            {'op': 'comment', 'ea': hex(ea), 'comment': 'fixture_changed'},
            {'op': 'comment', 'ea': hex(ea), 'comment': 'fixture_fail'}])
        assert result['rollback_complete'] and (idc.get_cmt(ea, False) or '') == before
    finally:
        plugin.idc.set_cmt = original_setter
    assert plugin.create_struct('struct ph4ntom_fixture_type { int value; };')['success']
    report.update(success=True, hexrays_available=plugin.HAS_HEXRAYS,
                  checks=['preview', 'rename', 'injected failure with real comment restoration', 'C type parse'])
except Exception:
    report['error'] = traceback.format_exc()
Path(os.environ['PH4NTOM_TEST_REPORT']).write_text(json.dumps(report), encoding='utf-8')
idc.qexit(0 if report['success'] else 1)
