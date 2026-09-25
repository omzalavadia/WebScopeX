# Architecture

WebScopeX keeps a deliberately simple local architecture:

```text
GUI / CLI
   ↓
Scanner orchestrator
   ├─ DNS / passive discovery
   ├─ live HTTP probing
   ├─ port/service discovery
   ├─ web fingerprinting / TLS
   ├─ content + crawler
   └─ JS / API / auth mapping
   ↓
Finding stream
   ├─ dashboard metrics
   ├─ Findings filters
   ├─ Recon Graph
   ├─ Delta Scan
   ├─ SQLite scan history
   └─ HTML / JSON / graph.json reports
```

## Recon Graph data model

Primary relations:

```text
domain → subdomain/host → IP
host → port → service
host → endpoint
host → technology
```

The graph is evidence-derived. The GUI renders a layered view; `graph.json` preserves the machine-readable nodes and edges.

## Scope Guard

Every HTTP request is checked against the declared scope root. Redirects that leave scope are discarded. Targets must equal the scope root or be its subdomain.
