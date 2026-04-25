"""Module entrypoint for ``python -m velloraq``.

The CLI remains intentionally thin: all command parsing and execution live in
``velloraq.cli.entrypoint`` so packaged console scripts and module execution
share one code path.
"""

# SPDX-License-Identifier: MIT
from velloraq.cli.entrypoint import main


if __name__ == "__main__":
    raise SystemExit(main())
