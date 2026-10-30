# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-30

### Added
- Interactive terminal UI using `questionary` and `rich`
- Authentication against local UDM Pro via the UniFi Integration API v1
- Zone-based firewall policy creation across multiple source/destination zone pairs in bulk
- Dry run mode — full preview table rendered without sending any requests to the controller
- Protocol filtering: TCP, UDP, TCP+UDP, or any
- Destination port filtering: manual entry, saved port list reference, or all ports
- Destination IP/subnet filtering
- Zone cluster support — group zones by name in `clusters.yaml` and select as a unit
- Port list management: view, create (with range support), and delete traffic matching lists
- Full site config backup via the legacy backup endpoint
- Optional AES-256-GCM encryption of backup files using scrypt key derivation
- Backup decryption flow (no controller connection required)
- `clusters.yaml` — safe to commit, contains no credentials
- Unit tests for crypto and policy builder modules
- Architecture documentation with Mermaid diagrams
