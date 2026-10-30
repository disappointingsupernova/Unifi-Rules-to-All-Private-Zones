"""Load and save zone cluster configuration and controller defaults from clusters.yaml."""

import shutil
import yaml
from pathlib import Path

try:
    import keyring
    _backend_name = type(keyring.get_keyring()).__module__
    _KEYRING_AVAILABLE = not any(
        bad in _backend_name for bad in ("fail", "null", "chainer", "alt")
    )
except Exception:
    _KEYRING_AVAILABLE = False

# clusters.yaml lives at the repo root, two levels above this file
CONFIG_PATH = Path(__file__).parent.parent.parent / "clusters.yaml"
EXAMPLE_PATH = CONFIG_PATH.parent / "clusters.example.yaml"

_KEYRING_SERVICE = "unifi-zone-manager"


def _ensure_config() -> None:
    """Copy clusters.example.yaml to clusters.yaml on first run if absent."""
    if not CONFIG_PATH.exists() and EXAMPLE_PATH.exists():
        shutil.copy(EXAMPLE_PATH, CONFIG_PATH)


def load_clusters() -> dict[str, list[str]]:
    """Return {cluster_name: [zone_name, ...]} or empty dict."""
    _ensure_config()
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH) as f:
        data = yaml.safe_load(f) or {}
    return data.get("clusters", {})


def load_controller_defaults() -> dict[str, str]:
    """Return {host, username} from the controller stanza, with empty-string defaults."""
    _ensure_config()
    if not CONFIG_PATH.exists():
        return {"host": "", "username": ""}
    with open(CONFIG_PATH) as f:
        data = yaml.safe_load(f) or {}
    ctrl = data.get("controller") or {}
    return {
        "host": str(ctrl.get("host") or "").strip(),
        "username": str(ctrl.get("username") or "").strip(),
    }


def save_controller_defaults(host: str, username: str) -> None:
    """Persist controller host and username (never password) to clusters.yaml."""
    existing: dict = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            existing = yaml.safe_load(f) or {}
    existing.setdefault("controller", {})
    existing["controller"]["host"] = host
    existing["controller"]["username"] = username
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(existing, f, default_flow_style=False, sort_keys=True)


def save_clusters(clusters: dict[str, list[str]]) -> None:
    existing: dict = {}
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            existing = yaml.safe_load(f) or {}
    existing["clusters"] = clusters
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(existing, f, default_flow_style=False, sort_keys=True)


def keyring_available() -> bool:
    return _KEYRING_AVAILABLE


def load_api_key(host: str) -> str | None:
    """Retrieve the API key for a given host from the OS keychain."""
    if not _KEYRING_AVAILABLE:
        return None
    try:
        return keyring.get_password(_KEYRING_SERVICE, host)
    except Exception:
        return None


def save_api_key(host: str, api_key: str) -> None:
    """Store the API key for a given host in the OS keychain."""
    if not _KEYRING_AVAILABLE:
        return
    keyring.set_password(_KEYRING_SERVICE, host, api_key)


def delete_api_key(host: str) -> None:
    """Remove the stored API key for a given host from the OS keychain."""
    if not _KEYRING_AVAILABLE:
        return
    try:
        keyring.delete_password(_KEYRING_SERVICE, host)
    except Exception:
        pass
