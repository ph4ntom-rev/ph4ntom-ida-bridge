1.  **Fix Flake8 and Autopep8 issues**
    -   `core/__init__.py`: Add `# noqa: F401` to exports.
    -   `ida_plugin/antigravity_server.py`: Remove unused imports or add `# noqa: F401` if they are dynamically tested. Remove unused local variables if safe, or prefix with `_` / comment out. Fix f-string missing placeholders. Remove `global _server` if not assigned.
    -   `integrations/ide_extension.py`: Remove unused imports `HTTPServer` and `BaseHTTPRequestHandler` if safe.
    -   `server.py`: Add `# noqa: F401` to unused dynamic IDA API imports `ida_bytes`, `ida_segment`, `ida_entry`, `ida_typeinf`.
    -   `verify_bridge.py`: Remove unused `os` and `pathlib.Path` if safe.
2.  **Ensure code quality**
    -   Run `flake8 .` and `autopep8 --in-place --recursive .`
    -   Run tests via `PYTHONPATH=. pytest tests/`
3.  **Perform pre-commit**
    -   Ensure proper testing, verifications, reviews and reflections are done.
4.  **Submit the change**
    -   Once everything is clean and tests pass, commit and push the changes.
