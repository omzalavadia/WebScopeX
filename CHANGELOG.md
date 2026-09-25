# WebScopeX changelog

# Changelog

## v3.0.0

- Upgraded Recon Graph to model domain → subdomain/host → IP → port → service and host → endpoint relationships.
- Added IP evidence during DNS/live-host discovery and service-aware Nmap XML parsing.
- Improved Delta Scan with added/removed/unchanged evidence and per-module change counts.
- Kept and polished the persistent Workspace system.
- Replaced the basic live-results table with a searchable/filterable Findings view and CSV export.
- Redesigned HTML reporting with responsive summary cards, graph inventory, filters, severity badges, JSON export, and `graph.json`.
- Added Tool Installer & Status Manager with fixed Windows install recipes for Nmap, ProjectDiscovery Go tools, ffuf, and wafw00f; WhatWeb remains manual on Windows.
- Expanded CLI with `--authorized`, `--modules`, `--list-modules`, and `--list-tools`.
- Added GitHub-ready docs, screenshot preview, MIT license, contribution guide, security policy, tests, and project metadata.
- Preserved v2.x scope guard, profiles, history, scan controls, reports, and enumeration engine.

## v2.1.0

- Added Workspaces, Recon Graph, Delta Scan, graph export, and CLI mode.

## v2.0.0

- Added modern dark dashboard, profiles, history, scope guard, external-tool status, and persistent reports.
