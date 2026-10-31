"""All interactive TUI flows for the UniFi Zone Firewall Rule Manager."""

import getpass
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from src.unifi_manager.api import UnifiClient, UnifiAPIError
from src.unifi_manager.config import load_clusters, save_clusters
from src.unifi_manager.crypto import decrypt_backup, encrypt_backup

console = Console()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def select_site(client: UnifiClient) -> str:
    with console.status("Fetching sites..."):
        sites = client.get_sites()
    if not sites:
        raise UnifiAPIError("No sites found.")
    if len(sites) == 1:
        console.print(f"[dim]Using site: {sites[0]['name']}[/dim]")
        return sites[0]["id"]
    choices = [f"{s['name']}  ({s['id']})" for s in sites]
    choice = questionary.select("Select site:", choices=choices).ask()
    return sites[choices.index(choice)]["id"]


def display_zones(zones: list[dict]) -> None:
    t = Table(title=f"Available Firewall Zones ({len(zones)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Name", style="cyan")
    t.add_column("Networks", style="green", justify="right")
    t.add_column("ID", style="dim")
    for i, z in enumerate(zones, 1):
        t.add_row(str(i), z["name"], str(len(z.get("networkIds", []))), z["id"])
    console.print(t)


def pick_zones(zones: list[dict], message: str) -> list[dict]:
    """Checkbox picker — also surfaces clusters as selectable options."""
    clusters = load_clusters()
    options = [z["name"] for z in zones]
    if clusters:
        options += [f"[CLUSTER] {name}" for name in clusters]

    selected = questionary.checkbox(message, choices=options).ask()
    if not selected:
        return []

    picked_names: set[str] = set()
    for s in selected:
        if s.startswith("[CLUSTER] "):
            picked_names.update(clusters.get(s[len("[CLUSTER] "):], []))
        else:
            picked_names.add(s)

    matched = [z for z in zones if z["name"] in picked_names]

    missing = picked_names - {z["name"] for z in matched}
    for m in missing:
        console.print(
            f"  [yellow]⚠ Zone '{m}' from cluster not found on controller — skipped.[/yellow]"
        )

    return matched


def _proto_label(protocol: str, ports: list[int], port_list_name: str | None) -> str:
    proto = protocol.upper()
    if port_list_name:
        return f"{proto} / list: {port_list_name}"
    if ports:
        return f"{proto} / ports: {', '.join(str(p) for p in ports)}"
    return f"{proto} / all ports"


# ---------------------------------------------------------------------------
# Policy builders
# ---------------------------------------------------------------------------

def build_ip_scope(protocol: str) -> dict:
    if protocol == "any":
        return {"ipVersion": "IPV4"}
    if protocol == "tcp+udp":
        return {
            "ipVersion": "IPV4",
            "protocolFilter": {
                "type": "PRESET",
                "preset": {"name": "TCP_UDP"},
            },
        }
    # TCP and UDP use NAMED_PROTOCOL with uppercase name
    return {
        "ipVersion": "IPV4",
        "protocolFilter": {
            "type": "NAMED_PROTOCOL",
            "matchOpposite": False,
            "protocol": {"name": protocol.upper()},
        },
    }


def build_port_filter_inline(ports: list[int]) -> dict:
    return {
        "type": "PORTS",
        "matchOpposite": False,
        "items": [{"type": "PORT_NUMBER", "portNumber": p} for p in ports],
    }


def build_port_filter_ref(list_id: str) -> dict:
    return {
        "type": "TRAFFIC_MATCHING_LIST",
        "matchOpposite": False,
        "trafficMatchingListId": list_id,
    }


def build_dest_traffic_filter(dest_ip: str, port_filter: dict | None) -> dict | None:
    if dest_ip and port_filter:
        return {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [
                    {"type": "SUBNET" if "/" in dest_ip else "IP_ADDRESS", "value": dest_ip}
                ],
            },
            "portFilter": port_filter,
        }
    if dest_ip:
        return {
            "type": "IP_ADDRESS",
            "ipAddressFilter": {
                "type": "IP_ADDRESSES",
                "matchOpposite": False,
                "items": [
                    {"type": "SUBNET" if "/" in dest_ip else "IP_ADDRESS", "value": dest_ip}
                ],
            },
        }
    if port_filter:
        return {"type": "PORT", "portFilter": port_filter}
    return None


def build_policy(
    name: str,
    description: str,
    source_zone_id: str,
    dest_zone_id: str,
    ip_scope: dict,
    dest_traffic_filter: dict | None,
) -> dict:
    policy: dict = {
        "name": name,
        "description": description,
        "enabled": True,
        "loggingEnabled": False,
        "action": {"type": "ALLOW", "allowReturnTraffic": True},
        "ipProtocolScope": ip_scope,
        "source": {"zoneId": source_zone_id},
        "destination": {"zoneId": dest_zone_id},
    }
    if dest_traffic_filter:
        policy["destination"]["trafficFilter"] = dest_traffic_filter
    return policy


def preview_policies(
    rule_name: str,
    description: str,
    protocol: str,
    ports: list[int],
    port_list_name: str | None,
    dest_ip: str,
    source_zones: list[dict],
    dest_zones: list[dict],
    dry_run: bool,
) -> None:
    """Print a full preview table of every policy that would be created."""
    console.print()
    console.print(Rule("[bold]Policy Preview[/bold]"))

    proto_label = _proto_label(protocol, ports, port_list_name)
    dest_label = dest_ip if dest_ip else "any"
    mode_label = (
        "[yellow bold]DRY RUN — nothing will be created[/yellow bold]"
        if dry_run
        else "[green]LIVE — will be created on confirm[/green]"
    )

    summary = (
        f"  Rule prefix : [cyan]{rule_name}[/cyan]\n"
        f"  Description : {description or '(none)'}\n"
        f"  Protocol    : [cyan]{proto_label}[/cyan]\n"
        f"  Dest IP     : [cyan]{dest_label}[/cyan]\n"
        f"  Mode        : {mode_label}\n"
        f"  Policies    : [bold]{len(source_zones) * len(dest_zones)}[/bold] "
        f"({len(source_zones)} source × {len(dest_zones)} destination)"
    )
    console.print(Panel(summary, title="Rule Configuration", expand=False))

    t = Table(show_lines=True, expand=False)
    t.add_column("#", style="dim", width=4)
    t.add_column("Policy Name", style="cyan")
    t.add_column("Source Zone", style="green")
    t.add_column("Destination Zone", style="blue")
    t.add_column("Protocol", style="magenta")
    t.add_column("Dest IP Filter", style="yellow")

    for n, (sz, dz) in enumerate(
        ((sz, dz) for sz in source_zones for dz in dest_zones), 1
    ):
        t.add_row(
            str(n),
            f"{rule_name} | {sz['name']} → {dz['name']}",
            sz["name"],
            dz["name"],
            proto_label,
            dest_label,
        )

    console.print(t)
    console.print()


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

def flow_create_rules(client: UnifiClient) -> None:
    with console.status("Fetching zones and port lists..."):
        zones = client.get_zones()
        all_lists = client.get_traffic_matching_lists()
        port_lists = [l for l in all_lists if l.get("type") == "PORTS"]

    display_zones(zones)

    console.print()
    dry_run = questionary.confirm(
        "Dry run? (preview only — nothing will be sent to the controller)", default=False
    ).ask()

    console.print(Rule("[dim]Step 1 — Rule details[/dim]"))
    rule_name = questionary.text("Rule name prefix (e.g. 'Allow Syslog'):").ask()
    if not rule_name:
        return
    description = questionary.text("Description (optional):").ask() or ""

    console.print(Rule("[dim]Step 2 — Protocol & ports[/dim]"))
    protocol = questionary.select(
        "Protocol:", choices=["udp", "tcp", "tcp+udp", "any"]
    ).ask()

    ports: list[int] = []
    port_list_id: str | None = None
    port_list_name: str | None = None

    if protocol != "any":
        port_source = questionary.select(
            "Port matching:",
            choices=["Enter ports manually", "Use a saved port list", "All ports (no port filter)"],
        ).ask()

        if port_source == "Enter ports manually":
            raw = questionary.text("Ports — comma separated (e.g. 514,515):").ask()
            if raw:
                try:
                    ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
                except ValueError:
                    console.print("[red]Invalid port numbers.[/red]")
                    return
            if not ports:
                console.print("[red]No valid ports entered.[/red]")
                return

        elif port_source == "Use a saved port list":
            if not port_lists:
                console.print(
                    "[yellow]No port lists found on controller. "
                    "Create one first via 'Manage port lists'.[/yellow]"
                )
                return
            choices = [
                f"{l['name']}  "
                f"({', '.join(str(i.get('value', i.get('start', ''))) for i in l.get('items', [])[:5])}"
                f"{'…' if len(l.get('items', [])) > 5 else ''})"
                for l in port_lists
            ]
            choice = questionary.select("Select port list:", choices=choices).ask()
            idx = choices.index(choice)
            port_list_id = port_lists[idx]["id"]
            port_list_name = port_lists[idx]["name"]

    console.print(Rule("[dim]Step 3 — Destination IP (optional)[/dim]"))
    dest_ip = (
        questionary.text(
            "Destination IP or subnet (e.g. 10.10.20.5 or 10.10.20.0/24) — leave blank for any:"
        ).ask()
        or ""
    )

    console.print(Rule("[dim]Step 4 — Source zones[/dim]"))
    source_zones = pick_zones(zones, "Select SOURCE zones (where traffic originates):")
    if not source_zones:
        console.print("[yellow]No source zones selected.[/yellow]")
        return
    console.print(
        "  Selected: " + ", ".join(f"[green]{z['name']}[/green]" for z in source_zones)
    )

    console.print(Rule("[dim]Step 5 — Destination zones[/dim]"))
    dest_zones = pick_zones(zones, "Select DESTINATION zones (where traffic is going):")
    if not dest_zones:
        console.print("[yellow]No destination zones selected.[/yellow]")
        return
    console.print(
        "  Selected: " + ", ".join(f"[blue]{z['name']}[/blue]" for z in dest_zones)
    )

    preview_policies(
        rule_name, description, protocol, ports, port_list_name,
        dest_ip, source_zones, dest_zones, dry_run,
    )

    if dry_run:
        console.print("[yellow]Dry run complete — no changes made.[/yellow]")
        return

    if not questionary.confirm(
        f"Create {len(source_zones) * len(dest_zones)} policies on the controller?",
        default=False,
    ).ask():
        console.print("[dim]Aborted.[/dim]")
        return

    ip_scope = build_ip_scope(protocol)
    if port_list_id:
        port_filter = build_port_filter_ref(port_list_id)
    elif ports:
        port_filter = build_port_filter_inline(ports)
    else:
        port_filter = None

    dest_traffic_filter = build_dest_traffic_filter(dest_ip, port_filter)

    console.print()
    created, failed = 0, 0
    for sz in source_zones:
        for dz in dest_zones:
            policy_name = f"{rule_name} | {sz['name']} → {dz['name']}"
            policy = build_policy(
                name=policy_name,
                description=description,
                source_zone_id=sz["id"],
                dest_zone_id=dz["id"],
                ip_scope=ip_scope,
                dest_traffic_filter=dest_traffic_filter,
            )
            try:
                client.create_policy(policy)
                console.print(f"  [green]✓[/green] {policy_name}")
                created += 1
            except UnifiAPIError as e:
                console.print(f"  [red]✗[/red] {policy_name}: {e}")
                failed += 1

    console.print(f"\n[bold]Done:[/bold] {created} created, {failed} failed.")


def flow_list_policies(client: UnifiClient) -> None:
    with console.status("Fetching policies..."):
        policies = client.get_policies()
    if not policies:
        console.print("[yellow]No policies found.[/yellow]")
        return
    t = Table(title=f"Firewall Policies ({len(policies)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Name", style="cyan")
    t.add_column("Action", style="bold")
    t.add_column("Enabled")
    t.add_column("Origin", style="dim")
    for i, p in enumerate(policies, 1):
        action = p.get("action", {}).get("type", "?")
        origin = p.get("metadata", {}).get("origin", "?")
        enabled = "[green]yes[/green]" if p.get("enabled") else "[red]no[/red]"
        t.add_row(str(i), p.get("name", ""), action, enabled, origin)
    console.print(t)


def flow_manage_port_lists(client: UnifiClient) -> None:
    while True:
        with console.status("Fetching port lists..."):
            all_lists = client.get_traffic_matching_lists()
        port_lists = [l for l in all_lists if l.get("type") == "PORTS"]

        action = questionary.select(
            "Port list management:",
            choices=["View port lists", "Create port list", "Delete port list", "Back"],
        ).ask()

        if action == "Back":
            break

        elif action == "View port lists":
            if not port_lists:
                console.print("[yellow]No port lists found.[/yellow]")
                continue
            t = Table(title=f"Port Lists ({len(port_lists)})", show_lines=True)
            t.add_column("Name", style="cyan")
            t.add_column("Ports", style="green")
            t.add_column("ID", style="dim")
            for l in port_lists:
                port_strs = [
                    str(item["portNumber"]) if item.get("type") == "PORT_NUMBER"
                    else f"{item['portRangeStart']}-{item['portRangeEnd']}"
                    for item in l.get("items", [])
                ]
                t.add_row(l["name"], ", ".join(port_strs), l["id"])
            console.print(t)

        elif action == "Create port list":
            name = questionary.text("Port list name:").ask()
            if not name:
                continue
            raw = questionary.text(
                "Ports — comma separated, ranges with hyphen (e.g. 80,443,8000-8080):"
            ).ask()
            if not raw:
                continue

            items: list[dict] = []
            try:
                for part in raw.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = part.split("-", 1)
                        items.append({"type": "PORT_NUMBER_RANGE", "portRangeStart": int(start), "portRangeEnd": int(end)})
                    else:
                        items.append({"type": "PORT_NUMBER", "portNumber": int(part)})
            except ValueError:
                console.print("[red]Invalid port format.[/red]")
                continue

            t = Table(title=f"New port list: {name}", show_lines=True)
            t.add_column("Type")
            t.add_column("Value")
            for item in items:
                if item["type"] == "PORT_NUMBER":
                    t.add_row("Single", str(item["portNumber"]))
                else:
                    t.add_row("Range", f"{item['portRangeStart']} – {item['portRangeEnd']}")
            console.print(t)

            if not questionary.confirm(
                f"Create port list '{name}' with {len(items)} entries?"
            ).ask():
                continue

            try:
                result = client.create_traffic_matching_list(
                    {"type": "PORTS", "name": name, "items": items}
                )
                console.print(
                    f"[green]✓ Created port list '{name}' (ID: {result.get('id', '?')})[/green]"
                )
            except UnifiAPIError as e:
                console.print(f"[red]Failed: {e}[/red]")

        elif action == "Delete port list":
            if not port_lists:
                console.print("[yellow]No port lists to delete.[/yellow]")
                continue
            choices = [f"{l['name']}  (ID: {l['id']})" for l in port_lists]
            choice = questionary.select("Select port list to delete:", choices=choices).ask()
            target = port_lists[choices.index(choice)]
            if not questionary.confirm(
                f"Delete '{target['name']}'? This cannot be undone."
            ).ask():
                continue
            try:
                client.delete_traffic_matching_list(target["id"])
                console.print(f"[green]✓ Deleted '{target['name']}'[/green]")
            except UnifiAPIError as e:
                console.print(f"[red]Failed: {e}[/red]")


def flow_backup(client: UnifiClient) -> None:
    encrypt = questionary.confirm("Encrypt backup with AES-256?").ask()
    password = None
    if encrypt:
        password = getpass.getpass("Encryption password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            console.print("[red]Passwords do not match.[/red]")
            return

    with console.status("Downloading backup..."):
        try:
            data = client.backup_site()
        except UnifiAPIError as e:
            console.print(f"[red]Backup failed: {e}[/red]")
            return

    if encrypt and password:
        data = encrypt_backup(data, password)
        ext = ".unf.enc"
    else:
        ext = ".unf"

    filename = f"unifi_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
    Path(filename).write_bytes(data)
    console.print(f"[green]Backup saved:[/green] {filename}")


def flow_decrypt_backup() -> None:
    path = questionary.path("Path to encrypted backup file:").ask()
    if not path or not Path(path).exists():
        console.print("[red]File not found.[/red]")
        return
    password = getpass.getpass("Decryption password: ")
    try:
        data = decrypt_backup(Path(path).read_bytes(), password)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        return
    out = path.replace(".enc", "")
    Path(out).write_bytes(data)
    console.print(f"[green]Decrypted to:[/green] {out}")


def flow_manage_clusters(zones: list[dict]) -> None:
    clusters = load_clusters()
    zone_names = [z["name"] for z in zones]

    action = questionary.select(
        "Cluster management:",
        choices=["View clusters", "Create/edit cluster", "Delete cluster", "Back"],
    ).ask()

    if action == "View clusters":
        if not clusters:
            console.print("[yellow]No clusters defined.[/yellow]")
            return
        t = Table(title="Zone Clusters", show_lines=True)
        t.add_column("Cluster", style="cyan")
        t.add_column("Zones", style="green")
        for name, members in clusters.items():
            t.add_row(name, ", ".join(members))
        console.print(t)

    elif action == "Create/edit cluster":
        name = questionary.text("Cluster name:").ask()
        if not name:
            return
        selected = questionary.checkbox(
            f"Select zones for cluster '{name}':",
            choices=zone_names,
            default=clusters.get(name, []),
        ).ask()
        clusters[name] = selected or []
        save_clusters(clusters)
        console.print(f"[green]Cluster '{name}' saved with {len(clusters[name])} zones.[/green]")

    elif action == "Delete cluster":
        if not clusters:
            console.print("[yellow]No clusters to delete.[/yellow]")
            return
        name = questionary.select("Delete cluster:", choices=list(clusters.keys())).ask()
        del clusters[name]
        save_clusters(clusters)
        console.print(f"[green]Cluster '{name}' deleted.[/green]")
