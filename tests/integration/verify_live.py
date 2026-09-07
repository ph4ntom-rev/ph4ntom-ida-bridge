"""Verify an installed MCP process against only the repository's live fixture."""
import argparse
import asyncio
import json
from pathlib import Path
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from core.client import BridgeClient


async def verify(args):
    report = {'success': False, 'checks': [], 'python': sys.executable}
    def passed(label):
        report['checks'].append(label)
    transport = StdioTransport(command=str(args.python.resolve()), args=['-I', '-m', 'mcp_server'],
                               cwd=str(args.python.resolve().parent), log_file=args.report.with_suffix('.stderr.log'))
    async with Client(transport) as client:
        async def call(name, arguments=None):
            result = await client.call_tool(name, arguments or {})
            assert not result.is_error
            return json.loads(result.content[0].text)
        tools = await client.list_tools()
        assert len(tools) == 54 and all(t.annotations is not None for t in tools)
        assert len(await client.list_resources()) == 2
        passed('installed stdio MCP registers 54 annotated tools and 2 resources')
        ping = await call('ping')
        assert ping['version'] == '6.2.0' and ping['auth_enabled'] and not ping['dynamic_exec_enabled']
        report['bridge'] = ping
        passed('authenticated MCP discovery reaches expected installed plugin version')
        info = await call('get_binary_info')
        assert info['filename'] == 'batch_fixture.exe' and Path(info['filepath']).resolve() == args.fixture.resolve(), 'Use only the repository fixture'
        passed('MCP reads the expected disposable database')
        resources = await client.read_resource('ida://info')
        assert json.loads(resources[0].text)['filename'] == 'batch_fixture.exe'
        passed('MCP resource returns authenticated database metadata')
        functions = await call('search_function', {'name': 'fixture_add'})
        ea = next(f['ea'] for f in functions['results'] if f['name'] == 'fixture_add')
        code = await call('decompile', {'ea': ea})
        assert 'return' in code['pseudocode'] and '+' in code['pseudocode']
        report['pseudocode'] = code['pseudocode']
        passed('MCP decompiles a real x64 function through Hex-Rays')
        for name in ('get_ctree', 'get_microcode', 'get_local_variables', 'get_function_details',
                     'get_xrefs_to', 'get_callers', 'get_call_graph', 'get_basic_blocks'):
            result = await call(name, {'ea': ea})
            assert result and not result.get('error')
            passed('MCP ' + name)
        ops = json.dumps([{'op': 'rename-func', 'ea': ea, 'name': 'fixture_mcp_verified'}])
        preview = await call('batch_mutations', {'mutations': ops, 'dry_run': True})
        assert preview['status'] == 'preview'
        assert (await call('decompile', {'ea': ea}))['name'] == 'fixture_add'
        passed('MCP batch preview leaves the function unchanged')
        try:
            assert (await call('rename_function', {'ea': ea, 'name': 'fixture_mcp_verified'}))['success']
            assert (await call('decompile', {'ea': ea}))['name'] == 'fixture_mcp_verified'
            passed('MCP rename is visible in fresh Hex-Rays output')
        finally:
            assert (await call('rename_function', {'ea': ea, 'name': 'fixture_add'}))['success']
        passed('MCP restores the original fixture function name')
        invalid = await client.call_tool('read_bytes', {'ea': ea, 'size': -1}, raise_on_error=False)
        assert invalid.is_error
        passed('invalid input becomes an MCP protocol error')
        disabled = await client.call_tool('execute_idapython', {'script': 'raise AssertionError("must not execute")'}, raise_on_error=False)
        assert disabled.is_error
        passed('MCP cannot execute scripts under default security settings')
        assert (await call('save_database'))['success']
        passed('MCP saves the current test database')
    with BridgeClient() as http:
        context = http.get('/api/macro/analyze_context', ea=ea)
        assert not context.get('error') and context.get('pseudocode') and context.get('callers')
        passed('REST combined context includes real pseudocode and callers')
        streams = []
        try:
            for _ in range(2):
                response = http.session.get(http.base_url + '/api/events', stream=True, timeout=2)
                response.raise_for_status()
                assert response.raw.readline() == b': connected\n'
                streams.append(response)
            passed('two concurrent authenticated event streams connect')
        finally:
            for stream in streams:
                stream.close()
    report['success'] = True
    args.report.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', type=Path, required=True, help='Installed MCP environment Python')
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    asyncio.run(verify(parser.parse_args()))
