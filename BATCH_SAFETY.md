# Batch preview and recovery

`POST /api/batch` accepts `mutations`, `dry_run` (default false) and `mode` (default `rollback`). MCP `batch_mutations` exposes the same options. The generic CLI can send this request with `api POST /api/batch --body ...`.

```json
{"dry_run":true,"mode":"rollback","mutations":[{"op":"rename-func","ea":"0x401000","name":"parse_header"},{"op":"comment","ea":"0x401000","comment":"Validated header entry"}]}
```

Replace the example address with a function in your database. A preview checks every operation's shape, addresses, function boundaries and rename collisions without writing. Execution repeats validation in the same main-thread callback as the changes, so there is no gap between validation and the first mutation. Maximum: 256 operations; unknown fields are rejected. C declarations and decompiler locals are not semantically evaluated during preview.

Default `rollback` mode supports `rename-func`, `comment-func` and `comment`. It saves each prior value immediately before the call, including a call that could modify the database and then raise. On error it restores in reverse order and reads each value back. Names are applied without `SN_FORCE`; collisions are rejected before any write. Function comments default to repeatable, address comments to non-repeatable; both accept an explicit boolean `repeatable`.

Inspect `phase`, `failed_at`, `rollback`, `rollback_complete` and `state`. `rolled_back` counts verified restorations, including a value that was already unchanged; it does not count scheduled undo actions. An SDK refusal or a readback mismatch yields `state: inspect_required`. `state: restored_values` refers only to saved name/comment text, not all IDA metadata or analysis side effects. This is not an IDB transaction or crash recovery. Save a database copy before broad edits.

`rename-var`, `create-struct` and `set-type` require explicit `mode: best_effort`. All input shapes are checked first, but execution stops at the first failure and leaves earlier changes in place. The failed operation may also have partial effects. This mode never claims rollback. Existing clients using these operations in an implicitly atomic batch must migrate.

C parser responses now use `parse_errors`: zero means success. The earlier `types_parsed` field incorrectly represented an error count. Header imports pass a validated filename with `PT_FILE`. This follows the [IDAPython parser contract](https://python.docs.hex-rays.com/idc/index.html#idc.parse_decls). Main-thread wrappers return the integer required by [execute_sync](https://python.docs.hex-rays.com/ida_kernwin/index.html#ida_kernwin.execute_sync), reject unexecuted callbacks and reuse an enclosing bridge callback.

## Verification

Run `python -m pytest -q` and `python -m flake8 . --select=F --exclude=.venv`. Runtime unit tests simulate IDA and cover invalid final operations with no writes, preview revalidation, SDK false results, mutate-then-raise, failed rollback, repeated comments, parser error counts and rejected main-thread scheduling.

For an optional real IDA check, compile `tests/fixtures/batch_fixture.c` into a local build directory with your C compiler, then run:

```text
python tests/integration/run_ida.py --ida /path/to/ida --fixture /path/to/compiled/batch_fixture
```

This requires a licensed IDA with IDAPython. The runner copies the fixture into a temporary directory and creates a fresh database, with a temporary token file and no HTTP listener. It checks preview, rename, real comment restoration after an injected failure and C type parsing. It prints the IDA version and results. It does not verify decompiler-local operations or all supported IDA versions. IDA was not available in the local implementation environment, so this integration check is supplied but has not been run there.
