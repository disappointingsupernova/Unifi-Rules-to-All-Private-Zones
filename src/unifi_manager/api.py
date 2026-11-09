"""UniFi Network API client for local UDM/controller access.

The Integration API (/proxy/network/integration) requires an API key
passed as the X-API-KEY request header. API keys are created in the
UniFi UI under Settings → Control Plane → Integrations.

The legacy backup endpoint (/proxy/network/api/s/default/cmd/backup)
still requires session-cookie auth via /api/auth/login.
"""

import requests
import urllib3
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UnifiAPIError(Exception):
    pass


class UnifiClient:
    def __init__(self, host: str):
        self.base = f"https://{host}"
        self.integration = f"{self.base}/proxy/network/integration"
        self.session = requests.Session()
        self.session.verify = False
        self.site_id: Optional[str] = None

    def set_api_key(self, api_key: str) -> None:
        """Configure the integration API key (X-API-KEY header)."""
        self.session.headers["X-API-KEY"] = api_key.strip()

    def login_for_backup(self, username: str, password: str) -> None:
        """Authenticate via session cookie — only needed for the backup endpoint."""
        resp = self.session.post(
            f"{self.base}/api/auth/login",
            json={"username": username, "password": password},
            timeout=10,
        )
        if resp.status_code != 200:
            raise UnifiAPIError(f"Login failed ({resp.status_code}): {resp.text}")

        token = resp.cookies.get("TOKEN")
        if not token:
            raw_headers = (
                resp.raw.headers.getlist("Set-Cookie")
                if hasattr(resp.raw.headers, "getlist")
                else [resp.raw.headers.get("Set-Cookie", "")]
            )
            for header_val in raw_headers:
                for part in header_val.split(";"):
                    if part.strip().startswith("TOKEN="):
                        token = part.strip()[len("TOKEN="):]
                        break
                if token:
                    break

        if not token:
            raise UnifiAPIError(
                "Login failed — no TOKEN cookie returned. "
                "Ensure you are using a local admin account, not a UI SSO account."
            )

        self.session.cookies.set("TOKEN", token, domain="", path="/")
        csrf = resp.headers.get("X-Csrf-Token") or resp.headers.get("X-CSRF-Token")
        if csrf:
            self.session.headers["X-Csrf-Token"] = csrf

    def logout(self) -> None:
        try:
            self.session.post(f"{self.base}/api/auth/logout", timeout=5)
        except Exception:
            pass

    def _get(self, path: str, retries: int = 3, **kwargs) -> dict:
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                resp = self.session.get(
                    f"{self.integration}{path}", timeout=30, **kwargs
                )
                if resp.status_code != 200:
                    raise UnifiAPIError(
                        f"GET {path} failed ({resp.status_code}): {resp.text}"
                    )
                return resp.json()
            except UnifiAPIError:
                raise
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    import time
                    time.sleep(1 * (attempt + 1))
        raise UnifiAPIError(f"GET {path} failed after {retries} attempts: {last_err}")

    def _post(self, path: str, payload: dict) -> dict:
        import json as _json
        resp = self.session.post(
            f"{self.integration}{path}", json=payload, timeout=30
        )
        if resp.status_code not in (200, 201):
            if resp.status_code == 500:
                raise UnifiAPIError(
                    f"POST {path} failed ({resp.status_code}): {resp.text}\n"
                    f"Payload: {_json.dumps(payload, indent=2)}"
                )
            raise UnifiAPIError(f"POST {path} failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def _get_all(self, path: str, page_size: int = 500, progress=None, task_id=None) -> list[dict]:
        """Fetch all pages from a paginated endpoint, parallelising after the first page."""
        first = self._get(path, params={"limit": page_size, "offset": 0})
        results: list[dict] = list(first.get("data", []))
        total = first.get("totalCount", 0)

        if progress and task_id is not None:
            progress.update(task_id, total=total, completed=len(results))

        if total <= page_size:
            if progress and task_id is not None:
                progress.update(task_id, completed=total)
            return results

        offsets = list(range(page_size, total, page_size))
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(len(offsets), 8)) as pool:
            futures = {
                pool.submit(self._get, path, params={"limit": page_size, "offset": o}): o
                for o in offsets
            }
            pages: dict[int, list[dict]] = {}
            for future in as_completed(futures):
                offset = futures[future]
                pages[offset] = future.result().get("data", [])
                if progress and task_id is not None:
                    progress.advance(task_id, len(pages[offset]))

        for o in sorted(offsets):
            results.extend(pages[o])

        return results

    def get_sites(self) -> list[dict]:
        data = self._get("/v1/sites")
        return data.get("data", [])

    def set_site(self, site_id: str) -> None:
        self.site_id = site_id

    def _site_path(self, path: str) -> str:
        if not self.site_id:
            raise UnifiAPIError("No site selected.")
        return f"/v1/sites/{self.site_id}{path}"

    def get_zones(self) -> list[dict]:
        return self._get_all(self._site_path("/firewall/zones"))

    def get_policies(self, progress=None, task_id=None) -> list[dict]:
        return self._get_all(
            self._site_path("/firewall/policies"),
            progress=progress,
            task_id=task_id,
        )

    def create_policy(self, policy: dict) -> dict:
        return self._post(self._site_path("/firewall/policies"), policy)

    def delete_policy(self, policy_id: str) -> None:
        resp = self.session.delete(
            f"{self.integration}{self._site_path(f'/firewall/policies/{policy_id}')}",
            timeout=30,
        )
        if resp.status_code != 200:
            raise UnifiAPIError(
                f"DELETE policy failed ({resp.status_code}): {resp.text}"
            )

    def get_policy(self, policy_id: str) -> dict:
        return self._get(self._site_path(f"/firewall/policies/{policy_id}"))

    def patch_policy(self, policy_id: str, payload: dict) -> dict:
        """PUT a full policy update — fetch existing first, merge name change, then PUT."""
        existing = self.get_policy(policy_id)
        # Build a PUT payload from the existing policy, overriding with payload fields
        put_payload = {
            "name": existing.get("name"),
            "description": existing.get("description", ""),
            "enabled": existing.get("enabled", True),
            "loggingEnabled": existing.get("loggingEnabled", False),
            "action": existing.get("action"),
            "ipProtocolScope": existing.get("ipProtocolScope"),
            "source": existing.get("source"),
            "destination": existing.get("destination"),
        }
        put_payload.update(payload)
        resp = self.session.put(
            f"{self.integration}{self._site_path(f'/firewall/policies/{policy_id}')}",
            json=put_payload,
            timeout=30,
        )
        if resp.status_code != 200:
            raise UnifiAPIError(f"PUT policy failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def get_traffic_matching_lists(self) -> list[dict]:
        return self._get_all(self._site_path("/traffic-matching-lists"))

    def get_traffic_matching_list(self, list_id: str) -> dict:
        return self._get(self._site_path(f"/traffic-matching-lists/{list_id}"))

    def create_traffic_matching_list(self, payload: dict) -> dict:
        return self._post(self._site_path("/traffic-matching-lists"), payload)

    def delete_traffic_matching_list(self, list_id: str) -> None:
        resp = self.session.delete(
            f"{self.integration}{self._site_path(f'/traffic-matching-lists/{list_id}')}",
            timeout=30,
        )
        if resp.status_code != 200:
            raise UnifiAPIError(
                f"DELETE traffic-matching-list failed ({resp.status_code}): {resp.text}"
            )

    def backup_site(self) -> bytes:
        """Download full site config backup via the legacy session-auth endpoint."""
        resp = self.session.post(
            f"{self.base}/proxy/network/api/s/default/cmd/backup",
            json={"cmd": "backup", "days": -1},
            timeout=60,
        )
        if resp.status_code != 200:
            raise UnifiAPIError(f"Backup failed ({resp.status_code}): {resp.text}")
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" in content_type:
            data = resp.json()
            url = data.get("data", [{}])[0].get("url")
            if not url:
                raise UnifiAPIError("Backup response had no download URL.")
            dl = self.session.get(f"{self.base}{url}", timeout=60)
            if dl.status_code != 200:
                raise UnifiAPIError(f"Backup download failed ({dl.status_code})")
            return dl.content
        return resp.content
