# Tool Manager

The built-in scanner does not require external reconnaissance tools. Optional integrations improve coverage or provide richer fingerprints.

## Automatic recipes on Windows

| Tool | Install path |
|---|---|
| Nmap | `winget` package |
| Subfinder | Go install |
| httpx | Go install |
| Naabu | Go install |
| Katana | Go install |
| Nuclei | Go install |
| ffuf | Go install |
| wafw00f | Python pip in the WebScopeX virtual environment |
| WhatWeb | Manual Windows setup recommended |

The Tool Status page detects installed binaries and exposes an **Install** button where an automatic recipe is defined. Recipes are fixed in source; the UI does not execute user-supplied shell commands.

When Go is missing, the manager can install the official Go package with `winget`. Restart WebScopeX if Windows has not refreshed PATH after an installation.
