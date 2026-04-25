# Legacy Import Compatibility

This package preserves compatibility with older imports, module execution, and the former scanner name.

The canonical package is now `velloraq`.

Current purpose:

- `python -m serverless_security_scanner` forwards to the Velloraq CLI.
- Legacy imports such as `serverless_security_scanner.models` forward to the matching `velloraq` modules.
- The `slssec` console command remains a compatibility alias for `velloraq`.

New scanner, API, report, rule, integration, and CLI code should be added under `velloraq/`.
