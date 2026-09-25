# CLI Guide

The CLI is useful for repeatable authorized enumeration and scripts.

## Standard profile

```bat
.venv\Scripts\python.exe webscopex.py --cli --authorized --target example.com --profile Standard
```

## Custom modules

```bat
.venv\Scripts\python.exe webscopex.py --cli --authorized --target example.com --scope example.com --modules dns,subdomains,live,ports,headers
```

## Options

- `--authorized` — required for CLI scanning.
- `--target` — domain or hostname.
- `--scope` — scope root; defaults to target.
- `--profile` — Quick, Standard, Deep, Custom.
- `--modules` — comma-separated module keys overriding the profile.
- `--output` — report root directory.
- `--delay` — delay between HTTP requests.
- `--list-modules` — print module names.
- `--list-tools` — print optional integration status.
