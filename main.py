"""
UniFi Zone Firewall Rule Manager — entry point.

Run with:
    python main.py

Authentication
--------------
The Integration API (/proxy/network/integration) requires an API key.
Create one in the UniFi UI: Settings → Control Plane → Integrations.

The legacy backup endpoint still uses session-cookie auth, so username
and password are only prompted when performing a backup.
"""

import sys
import getpass

import questionary
from rich.console import Console
from rich.panel import Panel

from src.unifi_manager.api import UnifiClient, UnifiAPIError
from src.unifi_manager.config import (
    load_controller_defaults,
    save_controller_defaults,
    load_api_key,
    save_api_key,
    delete_api_key,
    keyring_available,
)
from src.unifi_manager.ui.flows import (
    select_site,
    flow_create_rules,
    flow_list_policies,
    flow_manage_port_lists,
    flow_backup,
    flow_decrypt_backup,
    flow_manage_clusters,
)

console = Console()


def prompt_connection() -> tuple[str, str]:
    """Prompt for host and API key, pre-populating from keychain if available."""
    defaults = load_controller_defaults()
    host = questionary.text(
        "UDM/Controller IP or hostname:",
        default=defaults["host"],
    ).ask()
    if not host:
        console.print("[red]Cancelled.[/red]")
        sys.exit(0)
    host = host.strip()

    # Try to load API key from OS keychain
    stored_key = load_api_key(host)
    if stored_key:
        console.print("[dim]API key loaded from system keychain.[/dim]")
        use_stored = questionary.confirm(
            "Use stored API key?", default=True
        ).ask()
        if use_stored:
            return host, stored_key

    api_key = getpass.getpass("API key (Settings → Control Plane → Integrations): ")
    if not api_key:
        console.print("[red]Cancelled.[/red]")
        sys.exit(0)

    # Offer to save to keychain
    if keyring_available():
        if questionary.confirm(
            "Save API key to system keychain? (never written to disk)", default=True
        ).ask():
            save_api_key(host, api_key.strip())
            console.print("[dim]API key saved to system keychain.[/dim]")
    else:
        console.print(
            "[dim]Install 'keyring' to save the API key securely between sessions.[/dim]"
        )

    return host, api_key.strip()


def main() -> None:
    console.print(Panel("[bold cyan]UniFi Zone Firewall Rule Manager[/bold cyan]", expand=False))

    standalone = questionary.select(
        "What would you like to do?",
        choices=["Connect to controller", "Decrypt a backup file", "Exit"],
    ).ask()

    if standalone == "Decrypt a backup file":
        flow_decrypt_backup()
        return
    if standalone == "Exit":
        return

    host, api_key = prompt_connection()

    client = UnifiClient(host)
    try:
        client.set_api_key(api_key)

        with console.status("Connecting..."):
            sites = client.get_sites()
        if not sites:
            raise UnifiAPIError("No sites returned — check your API key and controller address.")
        console.print("[green]✓ Connected.[/green]")

        # Offer to save host as default (API key is never stored)
        defaults = load_controller_defaults()
        if host != defaults["host"]:
            if questionary.confirm(
                "Save host as default in clusters.yaml?", default=True
            ).ask():
                save_controller_defaults(host, defaults.get("username", ""))
                console.print("[dim]Host saved to clusters.yaml.[/dim]")

        # Site selection
        if len(sites) == 1:
            console.print(f"[dim]Using site: {sites[0]['name']}[/dim]")
            site_id = sites[0]["id"]
        else:
            choices = [f"{s['name']}  ({s['id']})" for s in sites]
            choice = questionary.select("Select site:", choices=choices).ask()
            site_id = sites[choices.index(choice)]["id"]
        client.set_site(site_id)

        with console.status("Fetching zones..."):
            zones = client.get_zones()
        console.print(f"[dim]Found {len(zones)} zones.[/dim]")

        while True:
            console.print()
            action = questionary.select(
                "Main menu:",
                choices=[
                    "Create firewall rules across zones",
                    "List existing policies",
                    "Manage port lists",
                    "Backup site config",
                    "Manage zone clusters",
                    "Forget stored API key",
                    "Exit",
                ],
            ).ask()

            if action == "Create firewall rules across zones":
                flow_create_rules(client)
            elif action == "List existing policies":
                flow_list_policies(client)
            elif action == "Manage port lists":
                flow_manage_port_lists(client)
            elif action == "Backup site config":
                # Backup uses the legacy endpoint which needs session auth
                console.print(
                    "[dim]Backup requires your username and password "
                    "(session auth, not API key).[/dim]"
                )
                username = questionary.text(
                    "Username:", default=defaults.get("username", "")
                ).ask()
                password = getpass.getpass("Password: ")
                if username and password:
                    try:
                        client.login_for_backup(username, password)
                        flow_backup(client)
                    except UnifiAPIError as e:
                        console.print(f"[red]Backup login failed: {e}[/red]")
            elif action == "Manage zone clusters":
                flow_manage_clusters(zones)
            elif action == "Forget stored API key":
                delete_api_key(host)
                console.print("[green]Stored API key removed from system keychain.[/green]")
            elif action == "Exit":
                break

    except UnifiAPIError as e:
        console.print(f"[red]API error: {e}[/red]")
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    finally:
        client.logout()
        console.print("[dim]Done.[/dim]")


if __name__ == "__main__":
    main()
