# Unifi-Rules-to-All-Private-Zones

> **GitHub:** [disappointingsupernova/Unifi-Rules-to-All-Private-Zones](https://github.com/disappointingsupernova/Unifi-Rules-to-All-Private-Zones)

Push firewall policies across multiple zones on a UDM Pro / UniFi Network Application (v10.x+) using the official Integration API.

## Features

- Interactive terminal UI (no browser needed, works over SSH)
- Create one firewall policy per source→destination zone pair in bulk
- Dry run mode — full preview table rendered without sending any requests to the controller
- Filter by protocol (TCP/UDP/TCP+UDP/ICMP/any), source IP/subnet, destination IP/subnet, and destination ports
- Use saved port lists (traffic matching lists) or enter ports inline; port ranges supported
- Extend existing rule groups to additional source or destination zones
- Rename managed rule groups (updates all policies in the group)
- Adopt unmanaged policies as managed — rename, re-prefix, and stamp with tool signature
- List all firewall policies with managed/unmanaged status
- Clean up unmanaged policies that are functionally identical to a managed one
- Manage port lists — view, create (with range support), and delete
- Zone clusters — group zones by name and select them as a unit
- Excluded zones — hide zones (e.g. External, Gateway, VPN) from bulk pickers via `clusters.yaml`
- Multi-site support — site selection when the controller hosts more than one site
- Full site config backup with optional AES-256-GCM encryption
- Decrypt encrypted backups (no controller connection required)
- Credentials are never stored — API key saved to OS keychain only if you opt in

## Requirements

- Python 3.11+
- UDM Pro running UniFi Network Application 10.x with zone-based firewall enabled
- A local admin account (not SSO)
- An API key — create one at **Settings → Control Plane → Integrations**

## Setup

```bash
pip install -r requirements.txt
```

`clusters.yaml` is created automatically from `clusters.example.yaml` on first run. You can also copy it manually:

```bash
cp clusters.example.yaml clusters.yaml
```

Edit `clusters.yaml` with your controller IP, any zone clusters, and zones to exclude from bulk pickers. This file is listed in `.gitignore` and will never be committed.

The API key is **never written to disk**. On first use you will be offered the option to save it to your OS keychain (Windows Credential Manager or macOS Keychain) so it is not re-entered every session. Use **Forget stored API key** from the main menu to remove it at any time.

> **Note:** Keyring support is available on Windows and macOS only. On Linux the keyring is disabled and the API key will be prompted each session.

## Usage

```bash
python main.py
```

You will be prompted for your controller IP and API key. The API key is created in the UniFi UI at **Settings → Control Plane → Integrations**.

### Main menu options

| Option | Description |
|---|---|
| Create firewall rules across zones | Bulk-create one policy per source→destination pair |
| Extend existing rules to more zones | Add new source or destination zones to an existing rule group |
| Rename managed rule group | Rename all policies in a group by changing their name prefix |
| Adopt unmanaged rules as managed | Stamp existing unmanaged policies with the tool signature |
| List existing policies | Show all policies with managed/unmanaged status |
| Clean up duplicate unmanaged policies | Remove unmanaged policies superseded by a managed equivalent |
| Manage port lists | View, create, or delete traffic matching port lists |
| Backup site config | Download a full site backup (plain or AES-256-GCM encrypted) |
| Manage zone clusters | Create, edit, or delete zone clusters |
| Forget stored API key | Remove the API key from the OS keychain |

## Zone Clusters

Edit `clusters.yaml` to pre-define groups of zones. Zone names must match exactly what appears in your UniFi controller. You can also create/edit clusters from within the tool via **Manage zone clusters**.

Example use case — allow UDP 514 (syslog) from all internal zones to your Monitoring zone:

1. Run `python main.py`
2. Connect to controller
3. Choose **Create firewall rules across zones**
4. Dry run: `No`
5. Protocol: `udp`, Port: `514`
6. Source: select `[CLUSTER] Internal` (or tick individual zones)
7. Destination: select your `Monitoring` zone
8. Confirm — one policy per source zone is created automatically

## Excluded Zones

Zones listed under `excluded_zones` in `clusters.yaml` are hidden from the zone picker during bulk operations. You will be asked at selection time whether to include them. Zone names are matched case-insensitively.

```yaml
excluded_zones:
  - External
  - Gateway
  - VPN
```

## Backup & Encryption

Backups are saved as `.unf` (plain) or `.unf.enc` (AES-256-GCM encrypted).  
To decrypt: run the tool and choose **Decrypt a backup file** from the opening menu (no controller connection needed).

Backup uses session-cookie authentication (separate from the API key). You will be prompted for your username and password only when performing a backup. The username is pre-filled from `clusters.yaml` if set.

## Notes

- The tool uses the `/proxy/network/integration` API (the official v1 Integration API), not the legacy `api/s/default` endpoints, except for backup which uses the legacy backup command.
- SSL verification is disabled for self-signed certs on local UDMs.
- `clusters.yaml` is listed in `.gitignore` — it contains your controller IP and username but no credentials. `clusters.example.yaml` is the committed template.
- Managed policies are identified by the `[unifi-zone-manager]` signature in their description field.
