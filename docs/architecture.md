# Architecture

**Repository:** [disappointingsupernova/Unifi-Rules-to-All-Private-Zones](https://github.com/disappointingsupernova/Unifi-Rules-to-All-Private-Zones)

This document describes the structure, data flow, and component relationships of the UniFi Zone Firewall Rule Manager.

---

## Repository Structure

```
unifi-zone-manager/
├── main.py                          # Entry point — thin orchestrator
├── clusters.yaml                    # User-defined zone clusters (no credentials)
├── pyproject.toml                   # Packaging, dependencies, tooling config
├── src/
│   └── unifi_manager/
│       ├── __init__.py              # Package version
│       ├── api.py                   # UniFi Integration API client
│       ├── config.py                # clusters.yaml load/save
│       ├── crypto.py                # AES-256-GCM backup encryption
│       └── ui/
│           ├── __init__.py
│           └── flows.py             # All interactive TUI flows
├── docs/
│   └── architecture.md             # This file
└── tests/
    ├── test_crypto.py
    └── test_policy_builders.py
```

---

## Component Diagram

```mermaid
graph TD
    A[main.py<br/>Entry Point] --> B[ui/flows.py<br/>TUI Flows]
    B --> C[api.py<br/>UniFi API Client]
    B --> D[config.py<br/>Cluster Config]
    B --> E[crypto.py<br/>AES-256-GCM]
    C -->|HTTPS / Integration API| F[(UDM Pro<br/>UniFi Network 10.x)]
    D -->|read/write| G[clusters.yaml]
    E -->|encrypt/decrypt| H[.unf.enc Backup Files]
```

---

## Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant M as main.py
    participant A as api.py
    participant UDM as UDM Pro

    U->>M: Enter host, username, password
    M->>A: login(username, password)
    A->>UDM: POST /api/auth/login
    UDM-->>A: 200 OK + Set-Cookie + X-CSRF-Token
    A->>A: Store cookie + CSRF header in session
    A-->>M: Login successful
    M->>A: get_sites()
    A->>UDM: GET /proxy/network/integration/v1/sites
    UDM-->>A: [{id, name, ...}]
    A-->>M: sites[]
    M->>U: Display site selector (if >1 site)
```

---

## Rule Creation Flow

```mermaid
flowchart TD
    Start([Start: Create Rules]) --> DryRun{Dry run?}
    DryRun -->|Yes| Collect[Collect rule details]
    DryRun -->|No| Collect

    Collect --> Name[Enter rule name & description]
    Name --> Proto[Select protocol: TCP / UDP / TCP+UDP / Any]
    Proto --> PortSrc{Port source}
    PortSrc -->|Manual| ManualPorts[Enter comma-separated ports]
    PortSrc -->|Saved list| PickList[Select from controller port lists]
    PortSrc -->|All ports| NoPorts[No port filter]

    ManualPorts --> DestIP
    PickList --> DestIP
    NoPorts --> DestIP

    DestIP[Optional: destination IP / subnet] --> SrcZones[Pick source zones<br/>individual or cluster]
    SrcZones --> DstZones[Pick destination zones<br/>individual or cluster]
    DstZones --> Preview[Render preview table<br/>N source × M destination policies]

    Preview --> DryCheck{Dry run?}
    DryCheck -->|Yes| Done([Done — no changes])
    DryCheck -->|No| Confirm{Confirm?}
    Confirm -->|No| Abort([Aborted])
    Confirm -->|Yes| Create[POST each policy to controller]
    Create --> Report[Print ✓ / ✗ per policy]
    Report --> Done2([Done])
```

---

## Backup & Encryption Flow

```mermaid
flowchart LR
    A[User triggers backup] --> B{Encrypt?}
    B -->|No| C[POST /api/s/default/cmd/backup]
    B -->|Yes| C
    C --> D{Response type}
    D -->|Direct binary| E[Write .unf file]
    D -->|JSON with URL| F[GET download URL]
    F --> E
    B -->|Yes| G[encrypt_backup\nscrypt KDF + AES-256-GCM]
    E --> G
    G --> H[Write .unf.enc file]

    I[User triggers decrypt] --> J[Read .unf.enc]
    J --> K[Verify UNIFIBAK1 magic]
    K --> L[scrypt derive key from password]
    L --> M[AES-256-GCM decrypt]
    M --> N[Write .unf file]
```

---

## Encrypted Backup File Format

```
┌─────────────────────────────────────────────────────────┐
│  Magic bytes  │  Salt (32B)  │  Nonce (12B)  │  Ciphertext + GCM tag  │
│  "UNIFIBAK1"  │  (random)    │  (random)     │  (AES-256-GCM)         │
└─────────────────────────────────────────────────────────┘
```

Key derivation: `scrypt(password, salt, N=2^17, r=8, p=1)` → 32-byte AES key.

---

## API Endpoints Used

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/auth/login` | POST | Authenticate, obtain session cookie + CSRF token |
| `/api/auth/logout` | POST | Invalidate session |
| `/proxy/network/integration/v1/sites` | GET | List sites, obtain `siteId` |
| `/proxy/network/integration/v1/sites/{siteId}/firewall/zones` | GET | List firewall zones |
| `/proxy/network/integration/v1/sites/{siteId}/firewall/policies` | GET | List existing policies |
| `/proxy/network/integration/v1/sites/{siteId}/firewall/policies` | POST | Create a firewall policy |
| `/proxy/network/integration/v1/sites/{siteId}/traffic-matching-lists` | GET | List port/IP matching lists |
| `/proxy/network/integration/v1/sites/{siteId}/traffic-matching-lists` | POST | Create a matching list |
| `/proxy/network/integration/v1/sites/{siteId}/traffic-matching-lists/{id}` | DELETE | Delete a matching list |
| `/proxy/network/api/s/default/cmd/backup` | POST | Trigger full site config backup (legacy endpoint) |
