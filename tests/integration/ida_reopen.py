"""Verify mutations persisted after IDA exited and reopened the saved fixture."""
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_hexrays
import ida_name
import ida_typeinf
import idc

report = {'success': False, 'checks': []}
try:
    assert Path(idc.get_input_file_path()).name.startswith('batch_fixture')
    ida_auto.auto_wait()
    ea = ida_name.get_name_ea(idc.BADADDR, 'ph4ntom_verified_fixture')
    assert ea != idc.BADADDR
    report['checks'].append('function name survives database reopen')
    variable = next(v for v in ida_hexrays.decompile(ea).lvars if v.name == 'fixture_arg')
    tif = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tif, None, 'unsigned int;', ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    assert variable.type() == tif
    report['checks'].append('local variable name and type survive database reopen')
    settings = ida_hexrays.lvar_uservec_t()
    assert ida_hexrays.restore_user_lvar_settings(settings, ea)
    assert any(item.cmt == 'persisted fixture comment' for item in settings.lvvec)
    report['checks'].append('local variable comment survives database reopen')
    assert idc.get_struc_size(idc.get_struc_id('ph4ntom_persist')) == 8
    assert idc.get_enum_width(idc.get_enum('ph4ntom_persist_enum')) == 2
    report['checks'].append('structure and enum width survive database reopen')
    report['success'] = True
except Exception:
    report['error'] = traceback.format_exc()
Path(os.environ['PH4NTOM_TEST_REPORT']).write_text(json.dumps(report), encoding='utf-8')
idc.qexit(0 if report['success'] else 1)
