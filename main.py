"""
UniFi Zone Firewall Rule Manager — entry point.

Run with:
    python main.py
"""

import sys
import getpass

import questionary
from rich.console import Console
from rich.panel import Panel

from src.unifi_manager.api import UnifiClient, UnifiAPIError
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


def prompt_credentials() -> tuple[str, str, str]:
    host = questionary.text("UDM/Controller IP or hostname:").ask()
    username = questionary.text("Username:").ask()
    password = getpass.getpass("Password: ")
    if not host or not username or not password:
        console.print("[red]Cancelled.[/red]")
        sys.exit(0)
    return host.strip(), username.strip(), password


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

    host, username, password = prompt_credentials()

    client = UnifiClient(host)
    try:
        with console.status("Logging in..."):
            client.login(username, password)
        console.print("[green]✓ Logged in.[/green]")

        site_id = select_site(client)
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
                flow_backup(client)
            elif action == "Manage zone clusters":
                flow_manage_clusters(zones)
            elif action == "Exit":
                break

    except UnifiAPIError as e:
        console.print(f"[red]API error: {e}[/red]")
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    finally:
        client.logout()
        console.print("[dim]Logged out.[/dim]")


if __name__ == "__main__":
    main()
