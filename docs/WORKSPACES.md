# Workspaces and Delta Scan

A workspace stores a name, target, scope root, and notes in the local SQLite database.

Delta Scan compares the current in-memory findings with the previous completed `report.json` for the same target. It shows added, removed, and unchanged evidence and a per-module change summary.

For clean comparisons, use the same scope and profile across repeated scans.
