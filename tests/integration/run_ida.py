"""Run licensed IDA against a copy of the compiled, repository-owned fixture."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ida', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='Compiled tests/fixtures/batch_fixture.c')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='ph4ntom-ida-test-') as directory:
        output = Path(directory)
        binary = output / ('batch_fixture' + args.fixture.suffix)
        shutil.copyfile(args.fixture, binary)
        script = output / 'ida_smoke.py'
        shutil.copyfile(Path(__file__).with_name('ida_smoke.py'), script)
        env = dict(os.environ, IDA_BRIDGE_TOKEN_FILE=str(output / 'token'),
                   PH4NTOM_TEST_PLUGIN=str(root / 'ida_plugin/ph4ntom_ida_bridge.py'),
                   PH4NTOM_TEST_REPORT=str(output / 'report.json'))
        result = subprocess.run([str(args.ida.resolve()), '-A', '-c', '-S"' + str(script) + '"',
                                 str(binary)], cwd=output, env=env, timeout=180,
                                capture_output=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        report = output / 'report.json'
        if not report.is_file():
            raise RuntimeError(f'IDA exited {result.returncode} without a report; check installation/license')
        data = json.loads(report.read_text(encoding='utf-8'))
        print(json.dumps(data, indent=2))
        if result.returncode != 0 or not data['success']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
