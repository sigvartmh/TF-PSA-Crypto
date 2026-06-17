# Local TF-PSA-Crypto checks (pixi)

Reproducible, locally runnable **code-style** and **ABI/API** checks for the
SPAKE2+ work, using [pixi](https://pixi.sh) so the exact toolchain is pinned.

```sh
cd checks
pixi shell            # activate the env (python, cmake, compiler, perl, ctags, ...)
# then:
pixi run code-style   # or  pixi run abi-check
```

(`pixi run <task>` also works without `pixi shell`.)

## code-style  (works on macOS and Linux)

`framework/scripts/code_style.py` requires **uncrustify exactly 0.75.1**, which is
not on conda-forge. The task builds that version from source once (cached in
`checks/.tools/uncrustify-0.75.1/`) and runs the check with it. Non-destructive by
default.

```sh
pixi run code-style                          # files changed since the upstream base
pixi run code-style -- drivers/builtin/src/spake2p.c   # specific files
pixi run code-style -- -f                     # fix in place
```

Status: the SPAKE2+ engine/driver/header pass (`Checked N files, style ok`).

## abi-check  (Linux only)

`scripts/abi_check.py` wraps **abi-dumper** + **abi-compliance-checker**, which
parse ELF DWARF debug info. They are not on conda-forge and do not work on macOS
(Mach-O), so this task only runs the comparison on **Linux x86_64**. It fetches the
two tools on first run and compares the upstream base against the SPAKE2+ branch:

```sh
# on a Linux runner:
cd checks && pixi run abi-check
# override the revisions compared:
SPAKE2P_ABI_OLD=<base> SPAKE2P_ABI_NEW=<branch> pixi run abi-check
```

On macOS the task prints why it cannot run and exits non-zero.

## Notes

- `.tools/` (built uncrustify, fetched ABI tools) and pixi's `.pixi/` / `pixi.lock`
  are local working artifacts; do not commit them.
- Defaults compare against the upstream base `665b2368a`; override with
  `SPAKE2P_BASE` (code-style) or `SPAKE2P_ABI_OLD`/`SPAKE2P_ABI_NEW` (abi-check).
