"""Load and save zone cluster configuration from clusters.yaml."""

import yaml
from pathlib import Path

# clusters.yaml lives at the repo root, two levels above this file
CONFIG_PATH = Path(__file__).parent.parent.parent / "clusters.yaml"


def load_clusters() -> dict[str, list[str]]:
    """Return {cluster_name: [zone_name, ...]} or empty dict."""
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH) as f:
        data = yaml.safe_load(f) or {}
    return data.get("clusters", {})


def save_clusters(clusters: dict[str, list[str]]) -> None:
    existing: dict = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            existing = yaml.safe_load(f) or {}
    existing["clusters"] = clusters
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(existing, f, default_flow_style=False, sort_keys=True)
