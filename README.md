# UniFi Zone Firewall Rule Manager

Push firewall policies across multiple zones on a UDM Pro / UniFi Network Application (v10.x+) using the official Integration API.

## Features

- Interactive terminal UI (no browser needed, works over SSH)
- Create one firewall policy per source→destination zone pair in bulk
- Filter by protocol (TCP/UDP/both/any), destination ports, and destination IP/subnet
- Zone clusters — group zones by name and select them as a unit
- Full site config backup with optional AES-256-GCM encryption
- Decrypt encrypted backups
- Credentials are never stored — prompted each session

## Requirements

- Python 3.11+
- UDM Pro running UniFi Network Application 10.x with zone-based firewall enabled
- A local admin account (not SSO)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

You will be prompted for your controller IP, username, and password each time.

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
- `clusters.yaml` is safe to commit — it contains no credentials.
