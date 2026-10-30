# Unifi-Rules-to-All-Private-Zones

> **GitHub:** [disappointingsupernova/Unifi-Rules-to-All-Private-Zones](https://github.com/disappointingsupernova/Unifi-Rules-to-All-Private-Zones)

Push firewall policies across multiple zones on a UDM Pro / UniFi Network Application (v10.x+) using the official Integration API.

## Features

- Interactive terminal UI (no browser needed, works over SSH)
- Create one firewall policy per source→destination zone pair in bulk
- Filter by protocol (TCP/UDP/both/any), destination ports, and destination IP/subnet
- Zone clusters — group zones by name and select them as a unit
- Full site config backup with optional AES-256-GCM encryption
- Decrypt encrypted backups
- Credentials are never stored — API key saved to OS keychain only if you opt in

## Requirements

- Python 3.11+
- UDM Pro running UniFi Network Application 10.x with zone-based firewall enabled
- A local admin account (not SSO)
- An API key — create one at **Settings → Control Plane → Integrations**

## Setup

```bash
pip install -r requirements.txt
cp clusters.example.yaml clusters.yaml
```

Edit `clusters.yaml` with your controller IP and any zone clusters. This file is listed in `.gitignore` and will never be committed. It is also created automatically from the example on first run.

The API key is **never written to disk**. On first use you will be offered the option to save it to your OS keychain (Windows Credential Manager, macOS Keychain, or Linux libsecret) so it is not re-entered every session. Use **Forget stored API key** from the main menu to remove it at any time.

## Usage

```bash
python main.py
```

You will be prompted for your controller IP and API key. The API key is created in the UniFi UI at **Settings → Control Plane → Integrations**.

## Zone Clusters

Edit `clusters.yaml` to pre-define groups of zones. Zone names must match exactly what appears in your UniFi controller. You can also create/edit clusters from within the tool via **Manage zone clusters**.

Example use case — allow UDP 514 (syslog) from all internal zones to your Monitoring zone:

1. Run `python main.py`
2. Connect to controller
3. Choose **Create firewall rules across zones**
4. Protocol: `udp`, Port: `514`
5. Source: select `[CLUSTER] Internal` (or tick individual zones)
6. Destination: select your `Monitoring` zone
7. Confirm — one policy per source zone is created automatically

## Backup & Encryption

Backups are saved as `.unf` (plain) or `.unf.enc` (AES-256-GCM encrypted).  
To decrypt: run the tool and choose **Decrypt a backup file** from the opening menu.

## Notes

- The tool uses the `/proxy/network/integration` API (the official v1 Integration API), not the legacy `api/s/default` endpoints, except for backup which uses the legacy backup command.
- SSL verification is disabled for self-signed certs on local UDMs.
- `clusters.yaml` is listed in `.gitignore` — it contains your controller IP but no credentials. `clusters.example.yaml` is the committed template.
