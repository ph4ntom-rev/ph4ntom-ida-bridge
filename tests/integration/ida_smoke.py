"""Executed by IDA in run_ida.py's disposable database, never an existing IDB."""
import importlib.util
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_kernwin
import ida_name
import idc
import ida_hexrays
import ida_bytes


report = {'success': False, 'ida_version': ida_kernwin.get_kernel_version(), 'results': []}


def check(name, operation, verify=None):
    try:
        result = operation()
        json.dumps(result, allow_nan=False)
        if isinstance(result, dict) and (result.get('error') or result.get('success') is False):
            raise AssertionError(str(result))
        if verify is not None:
            assert verify(result), str(result)
        report['results'].append({'check': name, 'success': True})
        return result
    except Exception:
        report['results'].append({'check': name, 'success': False, 'error': traceback.format_exc()})
        return None
try:
    if not Path(idc.get_input_file_path()).name.startswith('batch_fixture'):
        raise RuntimeError('Only the repository test fixture may be used')
    ida_auto.auto_wait()
    spec = importlib.util.spec_from_file_location('ph4ntom_fixture_plugin', os.environ['PH4NTOM_TEST_PLUGIN'])
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    ea = ida_name.get_name_ea(idc.BADADDR, 'fixture_add')
    assert ea != idc.BADADDR, 'Build the unstripped repository fixture'
    for name, arguments in [
        ('get_info', ()), ('get_functions', ()), ('get_functions_paginated', (0, 5)),
        ('get_strings', ()), ('get_imports', ()), ('get_exports', ()),
        ('get_segments', ()), ('get_structs', ()), ('get_enums', ()),
        ('get_local_types', ()), ('get_type_libraries', ()), ('get_names', ()),
        ('get_bookmarks', ()), ('get_patches', ()), ('get_function_gaps', ()),
        ('get_pseudocode', (ea,)), ('get_disasm', (ea,)), ('get_func_details', (ea,)),
        ('get_xrefs_to', (ea,)), ('get_xrefs_from', (ea,)), ('get_call_graph', (ea,)),
        ('get_basic_blocks', (ea,)), ('get_stack_vars', (ea,)), ('get_func_args', (ea,)),
        ('get_ctree_json', (ea,)), ('get_lvar_map', (ea,)), ('get_microcode', (ea,)),
        ('get_callers', (ea,)), ('get_callees', (ea,)), ('get_strings_used', (ea,)),
        ('read_bytes', (ea, 4)), ('get_instruction', (ea,)), ('get_operands', (ea,)),
        ('get_data_xrefs', (ea,)), ('get_code_xrefs', (ea,)), ('get_comment_at', (ea,)),
        ('get_analyze_context', (ea,)),
    ]:
        check(name, lambda name=name, arguments=arguments: getattr(plugin, name)(*arguments))
    check('context_has_pseudocode_and_callers', lambda: plugin.get_analyze_context(ea),
          lambda value: bool(value['pseudocode']) and bool(value['callers']) and bool(value['xrefs_to']))
    check('create_struct', lambda: plugin.create_struct('struct ph4ntom_fixture_type { int value; };'))
    check('add_struct_member', lambda: plugin.add_struct_member_api('ph4ntom_fixture_type', 'extra', 4, 4, 'int'))
    check('struct_readback', lambda: plugin.get_struct_details('ph4ntom_fixture_type'),
          lambda value: value['size'] == 8 and any(m['name'] == 'extra' for m in value['members']))
    check('delete_struct', lambda: plugin.delete_struct_api('ph4ntom_fixture_type'))
    check('create_enum', lambda: plugin.create_enum_api('ph4ntom_fixture_enum', 2))
    check('add_enum_member', lambda: plugin.add_enum_member_api('ph4ntom_fixture_enum', 'PH4NTOM_VALUE', 7))
    check('enum_readback', lambda: plugin.get_enum_details('ph4ntom_fixture_enum'),
          lambda value: any(m['value'] == 7 for m in value['members']))
    check('enum_width', plugin.get_enums, lambda value: any(e['name'] == 'ph4ntom_fixture_enum' and e['width'] == 2 for e in value['enums']))
    check('delete_enum', lambda: plugin.delete_enum_api('ph4ntom_fixture_enum'))
    old_var = ida_hexrays.decompile(ea).lvars[0].name
    check('rename_lvar', lambda: plugin.rename_local_var(ea, old_var, 'fixture_arg'),
          lambda value: 'fixture_arg' in [v.name for v in ida_hexrays.decompile(ea).lvars])
    check('set_lvar_type', lambda: plugin.set_lvar_type_api(ea, 'fixture_arg', 'unsigned int'))
    check('set_lvar_comment', lambda: plugin.set_lvar_comment_api(ea, 'fixture_arg', 'persisted fixture comment'))
    patch_ea = ida_name.get_name_ea(idc.BADADDR, 'fixture_patch_target')
    assert patch_ea != idc.BADADDR
    original_bytes = ida_bytes.get_bytes(patch_ea, 4)
    check('patch_bytes_verified', lambda: plugin.patch_bytes_at(patch_ea, '78563412'),
          lambda value: ida_bytes.get_bytes(patch_ea, 4) == bytes.fromhex('78563412'))
    check('patch_bytes_restore', lambda: plugin.patch_bytes_at(patch_ea, original_bytes.hex()),
          lambda value: ida_bytes.get_bytes(patch_ea, 4) == original_bytes)
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
    check('create_persistent_struct', lambda: plugin.create_struct('struct ph4ntom_persist { int a; int b; };'))
    check('create_persistent_enum', lambda: plugin.create_enum_api('ph4ntom_persist_enum', 2))
    check('save_current_database', plugin.save_database)
    report['_database_path'] = idc.get_idb_path()
    report.update(success=all(entry['success'] for entry in report['results']), hexrays_available=plugin.HAS_HEXRAYS,
                  checks=['preview', 'rename', 'injected failure with real comment restoration', 'C type parse'])
except Exception:
    report['error'] = traceback.format_exc()
Path(os.environ['PH4NTOM_TEST_REPORT']).write_text(json.dumps(report), encoding='utf-8')
idc.qexit(0 if report['success'] else 1)
