"""Load third-party rule plugins from explicit user-provided paths."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import importlib.util
from pathlib import Path

from velloraq.rules.base import Rule


def load_plugin_rules(plugin_dirs: list[str]) -> list[Rule]:
    """Import plugin modules and return rule instances they register."""

    rules: list[Rule] = []
    for plugin_dir in plugin_dirs:
        base = Path(plugin_dir)
        if not base.exists():
            continue
        files = [base] if base.is_file() else sorted(base.glob("*.py"))
        for path in files:
            if path.name.startswith("_") or path.suffix != ".py":
                continue
            module_name = f"velloraq_plugin_{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            register_rules = getattr(module, "register_rules", None)
            if callable(register_rules):
                loaded = register_rules()
                rules.extend(rule for rule in loaded if isinstance(rule, Rule))
    return rules
