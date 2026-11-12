# Raw Firmware, ASLR Addressing, ARM Thumb Vtables & Class Reconstruction

## 1. Raw Firmware (`imagebase == 0x0`) vs ASLR Module Addressing

| Property | Raw Firmware (`ROM @ 0xB8970000`, `RAM @ 0x8E100000`) | PE / ELF / Mach-O with ASLR (`target.dll`) |
|:---|:---|:---|
| `ida_nalt.get_imagebase()` | `0x0` | Preferred static base (or rebased load base) |
| `entry_point` | Often `BADADDR` (`null` in bridge `/api/info`) | Entry VA |
| Bridge `module_rva` format | `SEG+0xOFFSET` (e.g. `ROM+0x7498`, `RAM+0x120`) | `module.dll+0xOFFSET` (using live module base when debugging) |
| `parse_ea` inputs accepted | `0xb8977498`, symbol name (`checked before hex words like add/dead`), `ROM+0x7498` | `0x1800c3ea7`, symbol name, `target-1.dll+0xc3ea7` |
| Breakpoint persistence | **Absolute EA** (`0xb8977498`) — bare segment offset is ambiguous across multiple segments; no OS loader rebases raw firmware | **Module-relative `(module_name, rva)`** (`loc.set_rel_bpt("target.dll", runtime_ea - mod_base)`) |
| Breakpoint type in ROM/Flash | **Hardware execution BP** (`BPT_EXEC`, `size=4` on MIPS/ARM, `2` on Thumb) — flash/ROM (`kseg1`) ignores software `BREAK`/`BKPT` writes | Software BP (`BPT_SOFT`) in `.text` |

### MIPS32 Firmware Tips
- Check global pointer `$gp`-relative addressing (`lw $t9, offset($gp)`) when xrefs look sparse; ensure IDA's processor options have the right `$gp` value set.
- Uncached `kseg1` (`0xA0000000–0xBFFFFFFF`) and cached `kseg0` (`0x80000000–0x9FFFFFFF`) often alias physical memory (`phys = va & 0x1FFFFFFF`); check MMIO peripherals in `kseg1` (`0xB8000000+`).

## 2. ARM32 / Cortex-M Thumb Vtables & Vector Tables

On 32-bit ARM (especially Cortex-M, which executes **exclusively in Thumb mode**):
1. Every function pointer stored in a C++ `vtable`, callback struct, or Cortex-M interrupt vector table is a 4-byte little-endian `uint32_t` with **bit 0 set to `1`** (`func_ea | 1`) to select Thumb interworking state on `BX`/`BLX`/`LDR PC`.
2. **Never pass `raw_ptr` directly to `make_function` / `ida_funcs.add_func`** — clear bit 0 first:
   ```python
   func_ea = raw_ptr & ~1  # Strip Thumb interworking bit (LSB)
   ```
3. **MCP Shortcut**: `read_vtable(ea)` and `create_vtable_struct(ea, name)` in `ph4ntom-ida-bridge` v6.4.0 automatically strip bit `0` on 32-bit ARM, resolve demangled names and function prototypes, and deduplicate overloaded virtual method names!
4. If raw bytes at `func_ea` are decoded as ARM instead of Thumb, set segment register `T = 1` before `make_function`:
   ```python
   import ida_idp, ida_segregs, ida_funcs
   ida_segregs.split_sreg_range(func_ea, ida_idp.str2reg("T"), 1, ida_segregs.SR_user)
   ida_funcs.add_func(func_ea)
   ```

## 3. Reconstructing C++ / Rust / Go / Swift Classes (IDA 9.5+)

1. Query `list_classes(filter_pattern="...", toplevel_only=True)` and `get_class(name="...", render=True)` to inspect IDA 9.5's language-neutral Hex-Rays Class Model.
2. Locate constructor/destructor writes (`*this = &Class::vftable`) via `get_xrefs_to(vtable_ea)`.
3. Run `create_vtable_struct(ea=vtable_ea, name="Class_vtbl")`, then define `struct Class { Class_vtbl *__vftable; ... };` via `create_struct`, and retype `this` parameter via `set_function_type` or `set_variable_type`.
