"""All interactive TUI flows for the UniFi Zone Firewall Rule Manager."""

import getpass
import time
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console
from rich.markup import escape as markup_escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn
from rich.rule import Rule
from rich.table import Table

from src.unifi_manager.api import UnifiClient, UnifiAPIError
from src.unifi_manager.config import load_clusters, load_excluded_zones, save_clusters
from src.unifi_manager.crypto import decrypt_backup, encrypt_backup

console = Console()

TOOL_SIGNATURE = "[unifi-zone-manager]"


def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        console=console,
        transient=True,
    )


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


def pick_zones(zones: list[dict], message: str, allow_excluded: bool = False) -> list[dict]:
    """Checkbox picker — filters excluded zones by default, surfaces clusters."""
    clusters = load_clusters()
    excluded = load_excluded_zones()

    safe_zones = [z for z in zones if z["name"].lower() not in excluded]
    excluded_present = [z for z in zones if z["name"].lower() in excluded]

    if excluded_present and not allow_excluded:
        console.print(
            f"  [dim]{len(excluded_present)} zone(s) hidden by exclusion list "
            f"({', '.join(z['name'] for z in excluded_present)}). "
            f"Edit excluded_zones in clusters.yaml to change this.[/dim]"
        )

    working_zones = zones if allow_excluded else safe_zones

    options = [z["name"] for z in working_zones]
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
            f"  [yellow]Zone '{m}' from cluster not found on controller - skipped.[/yellow]"
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
        "items": [{"type": "PORT_NUMBER", "value": p} for p in ports],
    }


def build_port_filter_ref(list_id: str) -> dict:
    return {
        "type": "TRAFFIC_MATCHING_LIST",
        "matchOpposite": False,
        "trafficMatchingListId": list_id,
    }


def build_source_traffic_filter(source_ip: str) -> dict | None:
    if not source_ip:
        return None
    return {
        "type": "IP_ADDRESS",
        "ipAddressFilter": {
            "type": "IP_ADDRESSES",
            "matchOpposite": False,
            "items": [
                {"type": "SUBNET" if "/" in source_ip else "IP_ADDRESS", "value": source_ip}
            ],
        },
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
    source_traffic_filter: dict | None = None,
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
    if source_traffic_filter:
        policy["source"]["trafficFilter"] = source_traffic_filter
    if dest_traffic_filter:
        policy["destination"]["trafficFilter"] = dest_traffic_filter
    return policy


def preview_policies(
    rule_name: str,
    description: str,
    protocol: str,
    ports: list[int],
    port_list_name: str | None,
    source_ip: str,
    dest_ip: str,
    source_zones: list[dict],
    dest_zones: list[dict],
    dry_run: bool,
) -> None:
    console.print()
    console.print(Rule("[bold]Policy Preview[/bold]"))

    proto_label = _proto_label(protocol, ports, port_list_name)
    src_label = source_ip if source_ip else "any"
    dest_label = dest_ip if dest_ip else "any"
    mode_label = (
        "[yellow bold]DRY RUN - nothing will be created[/yellow bold]"
        if dry_run
        else "[green]LIVE - will be created on confirm[/green]"
    )

    summary = (
        f"  Rule prefix : [cyan]{rule_name}[/cyan]\n"
        f"  Description : {description or '(none)'}\n"
        f"  Protocol    : [cyan]{proto_label}[/cyan]\n"
        f"  Source IP   : [cyan]{src_label}[/cyan]\n"
        f"  Dest IP     : [cyan]{dest_label}[/cyan]\n"
        f"  Mode        : {mode_label}\n"
        f"  Policies    : [bold]{len(source_zones) * len(dest_zones)}[/bold] "
        f"({len(source_zones)} source x {len(dest_zones)} destination)"
    )
    console.print(Panel(summary, title="Rule Configuration", expand=False))

    t = Table(show_lines=True, expand=False)
    t.add_column("#", style="dim", width=4)
    t.add_column("Policy Name", style="cyan")
    t.add_column("Source Zone", style="green")
    t.add_column("Destination Zone", style="blue")
    t.add_column("Protocol", style="magenta")
    t.add_column("Src IP", style="yellow")
    t.add_column("Dest IP", style="yellow")

    for n, (sz, dz) in enumerate(
        ((sz, dz) for sz in source_zones for dz in dest_zones), 1
    ):
        t.add_row(
            str(n),
            f"{rule_name} | {sz['name']} -> {dz['name']}",
            sz["name"],
            dz["name"],
            proto_label,
            src_label,
            dest_label,
        )

    console.print(t)
    console.print()


def _policies_match(existing: dict, candidate: dict) -> bool:
    return (
        existing.get("source", {}).get("zoneId") == candidate["source"]["zoneId"]
        and existing.get("destination", {}).get("zoneId") == candidate["destination"]["zoneId"]
        and existing.get("ipProtocolScope") == candidate["ipProtocolScope"]
        and existing.get("destination", {}).get("trafficFilter") == candidate["destination"].get("trafficFilter")
        and existing.get("action", {}).get("type") == candidate["action"]["type"]
        and existing.get("enabled") == candidate["enabled"]
    )


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

def flow_create_rules(client: UnifiClient) -> None:
    from concurrent.futures import ThreadPoolExecutor
    with _make_progress() as progress:
        t_zones = progress.add_task("Fetching zones...", total=None)
        t_lists = progress.add_task("Fetching port lists...", total=None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_zones = pool.submit(client.get_zones)
            f_lists = pool.submit(client.get_traffic_matching_lists)
            zones = f_zones.result()
            progress.update(t_zones, total=len(zones), completed=len(zones))
            all_lists = f_lists.result()
            progress.update(t_lists, total=len(all_lists), completed=len(all_lists))
    port_lists = [l for l in all_lists if l.get("type") == "PORTS"]

    display_zones(zones)

    console.print()
    dry_run = questionary.confirm(
        "Dry run? (preview only - nothing will be sent to the controller)", default=False
    ).ask()

    console.print(Rule("[dim]Step 1 - Rule details[/dim]"))
    rule_name = questionary.text("Rule name prefix (e.g. 'Allow Syslog'):").ask()
    if not rule_name:
        return
    user_description = questionary.text("Description (optional):").ask() or ""
    description = f"{user_description} {TOOL_SIGNATURE}".strip()

    console.print(Rule("[dim]Step 2 - Protocol & ports[/dim]"))
    protocol = questionary.select(
        "Protocol:", choices=["udp", "tcp", "tcp+udp", "icmp", "any"]
    ).ask()

    ports: list[int] = []
    port_list_id: str | None = None
    port_list_name: str | None = None

    if protocol not in ("any", "icmp"):
        port_source = questionary.select(
            "Port matching:",
            choices=["Enter ports manually", "Use a saved port list", "All ports (no port filter)"],
        ).ask()

        if port_source == "Enter ports manually":
            raw = questionary.text("Ports - comma separated (e.g. 514,515):").ask()
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
                f"{'...' if len(l.get('items', [])) > 5 else ''})"
                for l in port_lists
            ]
            choice = questionary.select("Select port list:", choices=choices).ask()
            idx = choices.index(choice)
            port_list_id = port_lists[idx]["id"]
            port_list_name = port_lists[idx]["name"]

    console.print(Rule("[dim]Step 3 - Source IP (optional)[/dim]"))
    source_ip = (
        questionary.text(
            "Source IP or subnet (e.g. 10.10.20.5 or 10.10.20.0/24) - leave blank for any:"
        ).ask()
        or ""
    )

    console.print(Rule("[dim]Step 4 - Destination IP (optional)[/dim]"))
    dest_ip = (
        questionary.text(
            "Destination IP or subnet (e.g. 10.10.20.5 or 10.10.20.0/24) - leave blank for any:"
        ).ask()
        or ""
    )

    console.print(Rule("[dim]Step 5 - Source zones[/dim]"))
    include_excluded = questionary.confirm(
        "Include excluded zones (External, Gateway, VPN etc.)?", default=False
    ).ask()
    source_zones = pick_zones(
        zones, "Select SOURCE zones (where traffic originates):",
        allow_excluded=include_excluded,
    )
    if not source_zones:
        console.print("[yellow]No source zones selected.[/yellow]")
        return
    console.print(
        "  Selected: " + ", ".join(f"[green]{z['name']}[/green]" for z in source_zones)
    )

    console.print(Rule("[dim]Step 6 - Destination zones[/dim]"))
    dest_zones = pick_zones(
        zones, "Select DESTINATION zones (where traffic is going):",
        allow_excluded=include_excluded,
    )
    if not dest_zones:
        console.print("[yellow]No destination zones selected.[/yellow]")
        return
    console.print(
        "  Selected: " + ", ".join(f"[blue]{z['name']}[/blue]" for z in dest_zones)
    )

    preview_policies(
        rule_name, description, protocol, ports, port_list_name,
        source_ip, dest_ip, source_zones, dest_zones, dry_run,
    )

    if dry_run:
        console.print("[yellow]Dry run complete - no changes made.[/yellow]")
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
    source_traffic_filter = build_source_traffic_filter(source_ip)

    with _make_progress() as progress:
        t_existing = progress.add_task("Checking for existing policies...", total=None)
        existing_policies = client.get_policies(progress, t_existing)

    console.print()
    created, skipped, replaced, failed = 0, 0, 0, 0
    for sz in source_zones:
        for dz in dest_zones:
            policy_name = f"{rule_name} | {sz['name']} -> {dz['name']}"
            policy = build_policy(
                name=policy_name,
                description=description,
                source_zone_id=sz["id"],
                dest_zone_id=dz["id"],
                ip_scope=ip_scope,
                dest_traffic_filter=dest_traffic_filter,
                source_traffic_filter=source_traffic_filter,
            )

            exact = next(
                (p for p in existing_policies if p.get("name") == policy_name), None
            )
            if exact:
                console.print(f"  [dim]-[/dim] {policy_name} [dim](already exists, skipped)[/dim]")
                skipped += 1
                continue

            duplicate = next(
                (p for p in existing_policies
                 if _policies_match(p, policy)
                 and p.get("metadata", {}).get("origin") == "USER_DEFINED"),
                None,
            )

            try:
                result = client.create_policy(policy)
                new_id = result.get("id")
                console.print(f"  [green]OK[/green] {policy_name}")
                created += 1

                if duplicate and new_id:
                    try:
                        client.get_policy(new_id)
                        client.delete_policy(duplicate["id"])
                        console.print(
                            f"    [yellow]Replaced '{duplicate['name']}' "
                            f"(same rule, different name)[/yellow]"
                        )
                        replaced += 1
                        existing_policies = [p for p in existing_policies if p["id"] != duplicate["id"]]
                    except UnifiAPIError as e:
                        console.print(
                            f"    [red]Could not remove old policy '{duplicate['name']}': {e}[/red]"
                        )

                existing_policies.append(result)

            except UnifiAPIError as e:
                console.print(f"  [red]FAIL[/red] {policy_name}: {e}")
                failed += 1
            time.sleep(0.5)

    parts = [f"{created} created"]
    if replaced:
        parts.append(f"{replaced} replaced")
    if skipped:
        parts.append(f"{skipped} skipped (already existed)")
    if failed:
        parts.append(f"{failed} failed")
    console.print(f"\n[bold]Done:[/bold] {', '.join(parts)}.")


def flow_extend_rules(client: UnifiClient) -> None:
    """Find tool-created policies and extend them to additional zones."""
    from concurrent.futures import ThreadPoolExecutor
    with _make_progress() as progress:
        t_policies = progress.add_task("Fetching policies...", total=None)
        t_zones = progress.add_task("Fetching zones...", total=None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_policies = pool.submit(client.get_policies, progress, t_policies)
            f_zones = pool.submit(client.get_zones)
            zones = f_zones.result()
            progress.update(t_zones, total=len(zones), completed=len(zones))
            all_policies = f_policies.result()
    console.print(f"[dim]Loaded {len(all_policies)} policies, {len(zones)} zones.[/dim]")

    zone_id_map = {z["id"]: z["name"] for z in zones}

    tool_policies = [
        p for p in all_policies
        if TOOL_SIGNATURE in (p.get("description") or "")
    ]
    user_policies = [
        p for p in all_policies
        if p.get("metadata", {}).get("origin") == "USER_DEFINED"
    ]

    if not tool_policies:
        console.print(f"[yellow]No policies stamped with '{markup_escape(TOOL_SIGNATURE)}' found.[/yellow]")
        if not user_policies:
            console.print("[yellow]No user-defined policies found at all.[/yellow]")
            return
        if not questionary.confirm("Show all user-defined policies instead?", default=True).ask():
            return
        candidate_policies = user_policies
    else:
        candidate_policies = tool_policies

    groups: dict[str, list[dict]] = {}
    for p in candidate_policies:
        prefix = p["name"].split(" | ")[0].strip()
        groups.setdefault(prefix, []).append(p)

    t = Table(title=f"Rule Groups ({len(groups)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Rule Group", style="cyan")
    t.add_column("Policies", justify="right", style="green")
    t.add_column("Source Zones", style="dim")
    t.add_column("Dest Zones", style="dim")
    for i, (prefix, policies) in enumerate(groups.items(), 1):
        src_names = ", ".join({zone_id_map.get(p["source"]["zoneId"], "?") for p in policies})
        dst_names = ", ".join({zone_id_map.get(p["destination"]["zoneId"], "?") for p in policies})
        t.add_row(str(i), prefix, str(len(policies)), src_names, dst_names)
    console.print(t)

    group_choices = list(groups.keys())
    selected_group = questionary.select(
        "Select rule group to extend:",
        choices=group_choices,
    ).ask()
    if not selected_group:
        return

    template_policies = groups[selected_group]
    existing_source_ids = {p["source"]["zoneId"] for p in template_policies}
    existing_dest_ids = {p["destination"]["zoneId"] for p in template_policies}

    console.print(
        "\n[bold]Existing source zones:[/bold] "
        + ", ".join(f"[green]{zone_id_map.get(i, i)}[/green]" for i in existing_source_ids)
    )
    console.print(
        "[bold]Destination zones:[/bold] "
        + ", ".join(f"[blue]{zone_id_map.get(i, i)}[/blue]" for i in existing_dest_ids)
    )

    direction = questionary.select(
        "Extend by adding new:",
        choices=[
            "Source zones (same destinations, new sources)",
            "Destination zones (same sources, new destinations)",
        ],
    ).ask()
    extend_sources = direction.startswith("Source")

    if extend_sources:
        available_zones = [z for z in zones if z["id"] not in existing_source_ids]
        picker_message = "Select additional SOURCE zones to extend to:"
    else:
        available_zones = [z for z in zones if z["id"] not in existing_dest_ids]
        picker_message = "Select additional DESTINATION zones to extend to:"

    if not available_zones:
        console.print("[yellow]All zones are already covered by this rule group.[/yellow]")
        return

    include_excluded = questionary.confirm(
        "Include excluded zones (External, Gateway, VPN etc.)?", default=False
    ).ask()
    new_zones = pick_zones(available_zones, picker_message, allow_excluded=include_excluded)
    if not new_zones:
        console.print("[yellow]No zones selected.[/yellow]")
        return

    # Prefer a template with an explicit protocolFilter over ANY scope
    template = next(
        (p for p in template_policies if "protocolFilter" in p.get("ipProtocolScope", {})),
        template_policies[0],
    )
    ip_scope = template["ipProtocolScope"]
    description = template.get("description", TOOL_SIGNATURE)
    template_is_any_proto = "protocolFilter" not in ip_scope

    if template_is_any_proto:
        # Check if any template policy has a portFilter in its dest trafficFilter
        has_port_filter = any(
            "portFilter" in (p.get("destination", {}).get("trafficFilter") or {})
            for p in template_policies
        )
        if has_port_filter:
            console.print(
                "\n[yellow]Note: The template policies use ANY protocol scope with a port filter. "
                "The controller does not allow this combination — port filters will be "
                "stripped from the new policies.[/yellow]"
            )

    fixed_zones = [z for z in zones if z["id"] in (existing_dest_ids if extend_sources else existing_source_ids)]
    if extend_sources:
        pairs = [(new_z, fixed_z) for new_z in new_zones for fixed_z in fixed_zones]
    else:
        pairs = [(fixed_z, new_z) for fixed_z in fixed_zones for new_z in new_zones]

    def matching_for(dz: dict) -> dict | None:
        p = next((p for p in template_policies if p["destination"]["zoneId"] == dz["id"]), template)
        return p["destination"].get("trafficFilter")

    console.print()
    console.print(Rule("[bold]Extension Preview[/bold]"))
    pt = Table(show_lines=True, expand=False)
    pt.add_column("#", style="dim", width=4)
    pt.add_column("Policy Name", style="cyan")
    pt.add_column("Source Zone", style="green")
    pt.add_column("Destination Zone", style="blue")
    pt.add_column("Protocol", style="magenta")
    pt.add_column("Dest Filter", style="yellow")
    for n, (sz, dz) in enumerate(pairs, 1):
        # Summarise protocol from ip_scope
        proto = ip_scope.get("protocolFilter", {}).get("protocol", {}).get("name") \
            or ip_scope.get("protocolFilter", {}).get("preset", {}).get("name") \
            or "any"
        # Summarise dest traffic filter
        dtf = matching_for(dz)
        pf = dtf.get("portFilter", {}) if dtf else {}
        port_str = ", ".join(
            str(i.get("value", f"{i.get('start')}-{i.get('end')}"))
            for i in pf.get("items", [])
        ) if pf.get("items") else ""
        ip_str = ""
        if dtf and dtf.get("type") == "IP_ADDRESS":
            items = dtf.get("ipAddressFilter", {}).get("items", [])
            ip_str = ", ".join(i.get("value", "") for i in items)
        dest_filter = " / ".join(x for x in [ip_str, port_str] if x) or "any"
        pt.add_row(str(n), f"{selected_group} | {sz['name']} -> {dz['name']}", sz["name"], dz["name"], proto.upper(), dest_filter)
    console.print(pt)

    if not questionary.confirm(f"Create {len(pairs)} new policies?", default=False).ask():
        console.print("[dim]Aborted.[/dim]")
        return

    # Fetch existing policies for duplicate detection
    with _make_progress() as progress:
        t_ex = progress.add_task("Checking for existing policies...", total=None)
        existing_policies = client.get_policies(progress, t_ex)

    # Brief pause to let the UDM settle after the large fetch before POSTing
    time.sleep(2.0)

    created, skipped, failed = 0, 0, 0
    # Detect if template uses ANY protocol scope (no protocolFilter)
    template_is_any_proto = "protocolFilter" not in ip_scope

    for sz, dz in pairs:
        policy_name = f"{selected_group} | {sz['name']} -> {dz['name']}"
        matching = next(
            (p for p in template_policies if p["destination"]["zoneId"] == dz["id"]),
            template,
        )
        dest_traffic_filter = matching["destination"].get("trafficFilter")

        # Strip trafficFilters that cannot be safely cloned to a different destination zone:
        # - NETWORK type: networkIds are zone-specific, will 500 on a different dest zone
        # - ANY protocol + portFilter: controller rejects this combination
        if dest_traffic_filter:
            if dest_traffic_filter.get("type") == "NETWORK":
                dest_traffic_filter = None
            elif template_is_any_proto and "portFilter" in dest_traffic_filter:
                dest_traffic_filter = {k: v for k, v in dest_traffic_filter.items() if k != "portFilter"}
                if dest_traffic_filter.get("type") == "PORT":
                    dest_traffic_filter = None

        policy = build_policy(
            name=policy_name,
            description=description,
            source_zone_id=sz["id"],
            dest_zone_id=dz["id"],
            ip_scope=ip_scope,
            dest_traffic_filter=dest_traffic_filter,
        )

        exact = next((p for p in existing_policies if p.get("name") == policy_name), None)
        if exact:
            console.print(f"  [dim]-[/dim] {policy_name} [dim](already exists, skipped)[/dim]")
            skipped += 1
            continue

        for attempt in range(3):
            try:
                result = client.create_policy(policy)
                console.print(f"  [green]OK[/green] {policy_name}")
                created += 1
                existing_policies.append(result)
                break
            except UnifiAPIError as e:
                if "500" in str(e) and attempt < 2:
                    wait = 3.0 * (attempt + 1)
                    console.print(f"  [yellow]⟳[/yellow] {policy_name} [dim](500, retrying in {wait:.0f}s...)[/dim]")
                    time.sleep(wait)
                else:
                    console.print(f"  [red]FAIL[/red] {policy_name}: {e}")
                    failed += 1
                    break
        time.sleep(0.5)  # pace requests to avoid overwhelming the UDM

    parts = [f"{created} created"]
    if skipped:
        parts.append(f"{skipped} skipped (already existed)")
    if failed:
        parts.append(f"{failed} failed")
    console.print(f"\n[bold]Done:[/bold] {', '.join(parts)}.")


def flow_adopt_rules(client: UnifiClient) -> None:
    """Find unmanaged policies that share the same traffic pattern and adopt them as managed."""

    with _make_progress() as progress:
        t_pol = progress.add_task("Fetching policies...", total=None)
        t_zones = progress.add_task("Fetching zones...", total=None)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_pol = pool.submit(client.get_policies, progress, t_pol)
            f_zones = pool.submit(client.get_zones)
            zones = f_zones.result()
            progress.update(t_zones, total=len(zones), completed=len(zones))
            all_policies = f_pol.result()

    zone_id_map = {z["id"]: z["name"] for z in zones}

    unmanaged = [
        p for p in all_policies
        if TOOL_SIGNATURE not in (p.get("description") or "")
        and p.get("metadata", {}).get("origin") == "USER_DEFINED"
    ]

    if not unmanaged:
        console.print("[yellow]No unmanaged user-defined policies found.[/yellow]")
        return

    def _sig(p: dict) -> str:
        """Functional signature: source zone + protocol + dest traffic filter type/ports."""
        src = p.get("source", {}).get("zoneId", "")
        scope = p.get("ipProtocolScope", {})
        proto = (
            scope.get("protocolFilter", {}).get("protocol", {}).get("name")
            or scope.get("protocolFilter", {}).get("preset", {}).get("name")
            or "any"
        )
        dtf = p.get("destination", {}).get("trafficFilter") or {}
        pf = dtf.get("portFilter", {})
        ports = tuple(sorted(
            i.get("value", f"{i.get('start')}-{i.get('end')}")
            for i in pf.get("items", [])
        ))
        ip_items = tuple(sorted(
            i.get("value", "") for i in
            dtf.get("ipAddressFilter", {}).get("items", [])
        ))
        action = p.get("action", {}).get("type", "")
        return f"{src}|{proto}|{ports}|{ip_items}|{action}"

    # Group by signature
    groups: dict[str, list[dict]] = {}
    for p in unmanaged:
        groups.setdefault(_sig(p), []).append(p)

    # Only show groups with 2+ policies, sorted by count desc
    candidates = sorted(
        [(sig, pols) for sig, pols in groups.items() if len(pols) >= 2],
        key=lambda x: len(x[1]),
        reverse=True,
    )

    if not candidates:
        console.print("[yellow]No unmanaged policy groups with 2 or more matching policies found.[/yellow]")
        return

    # Display summary table
    t = Table(title=f"Unmanaged Policy Groups ({len(candidates)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Count", justify="right", style="bold green", width=6)
    t.add_column("Action", style="bold", width=8)
    t.add_column("Source Zone", style="green")
    t.add_column("Protocol", style="magenta")
    t.add_column("Ports / IP Filter", style="yellow")
    t.add_column("Destination Zones", style="blue")
    for i, (sig, pols) in enumerate(candidates, 1):
        p0 = pols[0]
        action = p0.get("action", {}).get("type", "?")
        action_str = f"[green]{action}[/green]" if action == "ALLOW" else f"[red]{action}[/red]"
        scope = p0.get("ipProtocolScope", {})
        proto = (
            scope.get("protocolFilter", {}).get("protocol", {}).get("name")
            or scope.get("protocolFilter", {}).get("preset", {}).get("name")
            or "any"
        ).upper()
        src_name = zone_id_map.get(p0.get("source", {}).get("zoneId", ""), "?")
        dtf = p0.get("destination", {}).get("trafficFilter") or {}
        pf = dtf.get("portFilter", {})
        port_str = ", ".join(
            str(i.get("value", f"{i.get('start')}-{i.get('end')}"))
            for i in pf.get("items", [])
        ) or "any"
        ip_str = ", ".join(
            i.get("value", "") for i in
            dtf.get("ipAddressFilter", {}).get("items", [])
        )
        filter_str = " / ".join(x for x in [port_str, ip_str] if x)
        dest_zones_str = ", ".join(
            zone_id_map.get(p.get("destination", {}).get("zoneId", ""), "?") for p in pols
        )
        t.add_row(str(i), str(len(pols)), action_str, src_name, proto, filter_str, dest_zones_str[:60])
    console.print(t)

    def _choice_label(pols: list[dict]) -> str:
        p0 = pols[0]
        action = p0.get("action", {}).get("type", "?")
        scope = p0.get("ipProtocolScope", {})
        proto = (
            scope.get("protocolFilter", {}).get("protocol", {}).get("name")
            or scope.get("protocolFilter", {}).get("preset", {}).get("name")
            or "any"
        ).upper()
        src = zone_id_map.get(p0.get("source", {}).get("zoneId", ""), "?")
        dtf = p0.get("destination", {}).get("trafficFilter") or {}
        pf = dtf.get("portFilter", {})
        ports = ", ".join(
            str(i.get("value", f"{i.get('start')}-{i.get('end')}"))
            for i in pf.get("items", [])
        ) or "any ports"
        return f"{len(pols):>3}x  [{action}] {proto} {ports} from {src}"

    choices = [_choice_label(pols) for _, pols in candidates]
    choice = questionary.select("Select group to adopt as managed:", choices=choices).ask()
    if not choice:
        return
    _, selected_policies = candidates[choices.index(choice)]

    # Show all policies in the group
    console.print()
    pt = Table(title=f"Policies in group ({len(selected_policies)})", show_lines=True)
    pt.add_column("#", style="dim", width=4)
    pt.add_column("Current Name", style="yellow")
    pt.add_column("Destination Zone", style="blue")
    for n, p in enumerate(selected_policies, 1):
        dst_name = zone_id_map.get(p.get("destination", {}).get("zoneId", ""), "?")
        pt.add_row(str(n), p.get("name", ""), dst_name)
    console.print(pt)

    # Suggest a name prefix built from the rule's actual components
    p0 = selected_policies[0]
    src_zone_name = zone_id_map.get(
        p0.get("source", {}).get("zoneId", ""), "?"
    )
    scope = p0.get("ipProtocolScope", {})
    proto = (
        scope.get("protocolFilter", {}).get("protocol", {}).get("name")
        or scope.get("protocolFilter", {}).get("preset", {}).get("name")
        or "any"
    ).upper()
    dtf = p0.get("destination", {}).get("trafficFilter") or {}
    pf = dtf.get("portFilter", {})
    port_str = ", ".join(
        str(i.get("value", f"{i.get('start')}-{i.get('end')}"))
        for i in pf.get("items", [])
    )
    ip_items = dtf.get("ipAddressFilter", {}).get("items", [])
    ip_str = ", ".join(i.get("value", "") for i in ip_items)

    # Check if a managed rule group already exists with the same traffic signature
    managed_policies = [
        p for p in all_policies
        if TOOL_SIGNATURE in (p.get("description") or "")
    ]
    managed_sig_map: dict[str, list[dict]] = {}
    for p in managed_policies:
        s = _sig(p)
        managed_sig_map.setdefault(s, []).append(p)

    selected_sig = _sig(selected_policies[0])
    # Also try a looser match on just source zone + ports + action
    # in case protocol scope differs between managed and unmanaged
    def _loose_sig(p: dict) -> str:
        src = p.get("source", {}).get("zoneId", "")
        dtf = p.get("destination", {}).get("trafficFilter") or {}
        pf = dtf.get("portFilter", {})
        ports = tuple(sorted(
            i.get("value", f"{i.get('start')}-{i.get('end')}")
            for i in pf.get("items", [])
        ))
        action = p.get("action", {}).get("type", "")
        return f"{src}|{ports}|{action}"

    selected_loose = _loose_sig(selected_policies[0])
    loose_managed_map: dict[str, list[dict]] = {}
    for p in managed_policies:
        loose_managed_map.setdefault(_loose_sig(p), []).append(p)

    matching_managed = managed_sig_map.get(selected_sig) or loose_managed_map.get(selected_loose, [])
    loose_match_only = not managed_sig_map.get(selected_sig) and bool(loose_managed_map.get(selected_loose))
    existing_managed_prefix: str | None = None
    if matching_managed:
        existing_managed_prefix = matching_managed[0]["name"].split(" | ")[0].strip()
        console.print(
            f"\n[green]Managed rule group already exists with the same traffic pattern:[/green] "
            f"[cyan]'{existing_managed_prefix}'[/cyan] ({len(matching_managed)} policies)"
        )
        if loose_match_only:
            # Show the protocol scope difference explicitly
            unmanaged_proto = proto
            managed_p0 = matching_managed[0]
            managed_scope = managed_p0.get("ipProtocolScope", {})
            managed_proto = (
                managed_scope.get("protocolFilter", {}).get("protocol", {}).get("name")
                or managed_scope.get("protocolFilter", {}).get("preset", {}).get("name")
                or "any"
            ).upper()
            console.print(
                f"\n[yellow bold]WARNING: Protocol scope mismatch[/yellow bold]\n"
                f"  Unmanaged policies : [red]{unmanaged_proto}[/red]\n"
                f"  Managed group      : [green]{managed_proto}[/green]\n"
                f"\n  Adopting these policies will rename and stamp them with the managed "
                f"group prefix, but will [bold]NOT[/bold] change their protocol scope on the controller.\n"
                f"  They will appear under the same group name but may behave differently "
                f"to the existing managed policies."
            )
            if not questionary.confirm(
                "I understand the protocol scope differs — proceed anyway?", default=False
            ).ask():
                existing_managed_prefix = None
            elif not questionary.confirm(
                f"Adopt into existing group '{existing_managed_prefix}'?", default=True
            ).ask():
                existing_managed_prefix = None
            else:
                suggested = existing_managed_prefix
                # Offer to normalise protocol scope to match the managed group
                normalise_proto = questionary.confirm(
                    f"Also normalise protocol scope from {unmanaged_proto} to {managed_proto} "
                    f"on the controller? (recommended)", default=True
                ).ask()
                if normalise_proto:
                    # Build the target ip_scope from the managed group's template
                    managed_ip_scope = matching_managed[0].get("ipProtocolScope")
                else:
                    managed_ip_scope = None
        else:
            if not questionary.confirm(
                f"Adopt into existing group '{existing_managed_prefix}'?", default=True
            ).ask():
                existing_managed_prefix = None
            else:
                suggested = existing_managed_prefix

    if not existing_managed_prefix:
        action_word = p0.get("action", {}).get("type", "ALLOW").capitalize()
        parts = [action_word, proto]
        if port_str:
            parts.append(port_str)
        if ip_str:
            parts += ["to", ip_str]
        parts += ["from", src_zone_name, "to Destinations"]
        suggested = " ".join(parts)

        new_prefix = questionary.text(
            "New managed rule name prefix:",
            default=suggested,
        ).ask()
        if not new_prefix:
            return
    else:
        new_prefix = existing_managed_prefix

    # Preview renames
    console.print()
    console.print(Rule("[bold]Adoption Preview[/bold]"))
    prev = Table(show_lines=True, expand=False)
    prev.add_column("#", style="dim", width=4)
    prev.add_column("Current Name", style="yellow")
    prev.add_column("New Managed Name", style="green")
    for n, p in enumerate(selected_policies, 1):
        dst_name = zone_id_map.get(p.get("destination", {}).get("zoneId", ""), "?")
        new_name = f"{new_prefix} | {src_zone_name} -> {dst_name}"
        prev.add_row(str(n), p.get("name", ""), new_name)
    console.print(prev)

    if not questionary.confirm(
        f"Adopt {len(selected_policies)} policies as managed (rename + stamp description)?",
        default=False,
    ).ask():
        console.print("[dim]Aborted.[/dim]")
        return

    adopted, failed = 0, 0
    for p in selected_policies:
        dst_name = zone_id_map.get(p.get("destination", {}).get("zoneId", ""), "?")
        new_name = f"{new_prefix} | {src_zone_name} -> {dst_name}"
        existing_desc = (p.get("description") or "").replace(TOOL_SIGNATURE, "").strip()
        new_desc = f"{existing_desc} {TOOL_SIGNATURE}".strip()
        patch: dict = {"name": new_name, "description": new_desc}
        # If normalising protocol scope, include the target ipProtocolScope
        if locals().get("managed_ip_scope"):
            patch["ipProtocolScope"] = managed_ip_scope
        try:
            client.patch_policy(p["id"], patch)
            console.print(f"  [green]OK[/green] {p['name']} -> {new_name}")
            adopted += 1
        except UnifiAPIError as e:
            console.print(f"  [red]FAIL[/red] {p['name']}: {e}")
            failed += 1

    console.print(f"\n[bold]Done:[/bold] {adopted} adopted, {failed} failed.")


def flow_normalise_group(client: UnifiClient) -> None:
    """Find managed rule groups with inconsistent protocol scopes and fix them."""
    with _make_progress() as progress:
        t_pol = progress.add_task("Fetching policies...", total=None)
        all_policies = client.get_policies(progress, t_pol)

    managed = [p for p in all_policies if TOOL_SIGNATURE in (p.get("description") or "")]
    if not managed:
        console.print("[yellow]No managed policies found.[/yellow]")
        return

    # Group by prefix, build per-group protocol breakdown
    groups: dict[str, list[dict]] = {}
    for p in managed:
        prefix = p["name"].split(" | ")[0].strip()
        groups.setdefault(prefix, []).append(p)

    def _proto_of(p: dict) -> str:
        scope = p.get("ipProtocolScope", {})
        return (
            scope.get("protocolFilter", {}).get("protocol", {}).get("name")
            or scope.get("protocolFilter", {}).get("preset", {}).get("name")
            or "ANY"
        ).upper()

    mixed_groups = {
        prefix: pols
        for prefix, pols in groups.items()
        if len({_proto_of(p) for p in pols}) > 1
    }

    if not mixed_groups:
        console.print("[green]All managed rule groups have consistent protocol scopes.[/green]")
        return

    console.print(f"\n[bold]{len(mixed_groups)} rule group(s) have mixed protocol scopes.[/bold]\n")

    for prefix, policies in mixed_groups.items():
        # Build breakdown: {proto: [policies]}
        breakdown: dict[str, list[dict]] = {}
        for p in policies:
            breakdown.setdefault(_proto_of(p), []).append(p)

        # Show breakdown table
        t = Table(title=f"{prefix} — protocol breakdown", show_lines=True)
        t.add_column("Protocol", style="cyan")
        t.add_column("Count", justify="right", style="green")
        t.add_column("Example policies", style="dim")
        for proto, pols in sorted(breakdown.items(), key=lambda x: -len(x[1])):
            examples = ", ".join(p["name"].split(" | ")[-1] for p in pols[:3])
            if len(pols) > 3:
                examples += f" (+{len(pols)-3} more)"
            t.add_row(proto, str(len(pols)), examples)
        console.print(t)

        # Ask which protocol to normalise to
        proto_choices = sorted(breakdown.keys(), key=lambda k: -len(breakdown[k]))
        target_proto = questionary.select(
            f"Normalise '{prefix}' to which protocol?",
            choices=proto_choices + ["Skip this group"],
        ).ask()

        if target_proto == "Skip this group":
            console.print("  [dim]Skipped.[/dim]\n")
            continue

        target_scope = breakdown[target_proto][0].get("ipProtocolScope")
        to_fix = [p for p in policies if _proto_of(p) != target_proto]

        # Preview
        pt = Table(show_lines=True, expand=False)
        pt.add_column("Policy", style="yellow")
        pt.add_column("From", style="red")
        pt.add_column("To", style="green")
        for p in to_fix:
            pt.add_row(p["name"], _proto_of(p), target_proto)
        console.print(pt)

        if not questionary.confirm(
            f"Update {len(to_fix)} policies to {target_proto}?", default=True
        ).ask():
            console.print("  [dim]Skipped.[/dim]\n")
            continue

        fixed, failed = 0, 0
        for p in to_fix:
            try:
                client.patch_policy(p["id"], {"ipProtocolScope": target_scope})
                console.print(f"  [green]OK[/green] {p['name']}: {_proto_of(p)} -> {target_proto}")
                fixed += 1
                time.sleep(0.3)
            except UnifiAPIError as e:
                console.print(f"  [red]FAIL[/red] {p['name']}: {e}")
                failed += 1
        console.print(f"  {fixed} fixed, {failed} failed.\n")


def flow_rename_rules(client: UnifiClient) -> None:
    """Rename a group of managed policies by changing their name prefix."""
    with _make_progress() as progress:
        t_pol = progress.add_task("Fetching policies...", total=None)
        all_policies = client.get_policies(progress, t_pol)

    managed = [p for p in all_policies if TOOL_SIGNATURE in (p.get("description") or "")]

    if not managed:
        console.print(f"[yellow]No managed policies found (stamped with '{markup_escape(TOOL_SIGNATURE)}').[/yellow]")
        return

    groups: dict[str, list[dict]] = {}
    for p in managed:
        prefix = p["name"].split(" | ")[0].strip()
        groups.setdefault(prefix, []).append(p)

    t = Table(title=f"Managed Rule Groups ({len(groups)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Current Prefix", style="cyan")
    t.add_column("Policies", justify="right", style="green")
    for i, (prefix, policies) in enumerate(groups.items(), 1):
        t.add_row(str(i), prefix, str(len(policies)))
    console.print(t)

    selected_prefix = questionary.select(
        "Select rule group to rename:",
        choices=list(groups.keys()),
    ).ask()
    if not selected_prefix:
        return

    new_prefix = questionary.text(
        f"New name prefix (current: '{selected_prefix}'):",
        default=selected_prefix,
    ).ask()
    if not new_prefix or new_prefix == selected_prefix:
        console.print("[dim]No change.[/dim]")
        return

    policies_to_rename = groups[selected_prefix]

    # Preview
    console.print()
    console.print(Rule("[bold]Rename Preview[/bold]"))
    pt = Table(show_lines=True, expand=False)
    pt.add_column("#", style="dim", width=4)
    pt.add_column("Current Name", style="yellow")
    pt.add_column("New Name", style="green")
    for n, p in enumerate(policies_to_rename, 1):
        suffix = p["name"][len(selected_prefix):]
        new_name = new_prefix + suffix
        pt.add_row(str(n), p["name"], new_name)
    console.print(pt)

    if not questionary.confirm(
        f"Rename {len(policies_to_rename)} policies?", default=False
    ).ask():
        console.print("[dim]Aborted.[/dim]")
        return

    renamed, failed = 0, 0
    for p in policies_to_rename:
        suffix = p["name"][len(selected_prefix):]
        new_name = new_prefix + suffix
        try:
            client.patch_policy(p["id"], {"name": new_name})
            console.print(f"  [green]OK[/green] {p['name']} -> {new_name}")
            renamed += 1
        except UnifiAPIError as e:
            console.print(f"  [red]FAIL[/red] {p['name']}: {e}")
            failed += 1

    console.print(f"\n[bold]Done:[/bold] {renamed} renamed, {failed} failed.")


def flow_cleanup_duplicates(client: UnifiClient) -> None:
    """Find unmanaged policies that are functionally identical to a managed one and offer to remove them."""
    with _make_progress() as progress:
        t_pol = progress.add_task("Fetching policies...", total=None)
        all_policies = client.get_policies(progress, t_pol)

    managed = [p for p in all_policies if TOOL_SIGNATURE in (p.get("description") or "")]
    unmanaged = [
        p for p in all_policies
        if TOOL_SIGNATURE not in (p.get("description") or "")
        and p.get("metadata", {}).get("origin") == "USER_DEFINED"
    ]

    if not managed:
        console.print(f"[yellow]No managed policies (stamped with '{markup_escape(TOOL_SIGNATURE)}') found.[/yellow]")
        return

    # Find unmanaged policies that are functionally identical to a managed one
    duplicates: list[tuple[dict, dict]] = []  # (unmanaged, managed_equivalent)
    for u in unmanaged:
        equiv = next((m for m in managed if _policies_match(u, m)), None)
        if equiv:
            duplicates.append((u, equiv))

    if not duplicates:
        console.print("[green]No duplicate unmanaged policies found.[/green]")
        return

    console.print(f"\n[bold]{len(duplicates)} unmanaged policies have a managed equivalent:[/bold]\n")

    deleted, kept = 0, 0
    for u, m in duplicates:
        t = Table(show_lines=True, expand=False)
        t.add_column("Field", style="dim")
        t.add_column("Unmanaged (to remove)", style="yellow")
        t.add_column("Managed (to keep)", style="green")
        t.add_row("Name", u.get("name", ""), m.get("name", ""))
        t.add_row("Origin", u.get("metadata", {}).get("origin", ""), m.get("metadata", {}).get("origin", ""))
        t.add_row("Description", u.get("description") or "(none)", m.get("description") or "(none)")
        console.print(t)

        if questionary.confirm(
            f"Delete unmanaged policy '{u['name']}'?", default=False
        ).ask():
            try:
                client.delete_policy(u["id"])
                console.print(f"  [green]Deleted '{u['name']}'[/green]")
                deleted += 1
            except UnifiAPIError as e:
                console.print(f"  [red]Failed to delete '{u['name']}': {e}[/red]")
        else:
            console.print(f"  [dim]Kept '{u['name']}'[/dim]")
            kept += 1
        console.print()

    console.print(f"[bold]Done:[/bold] {deleted} deleted, {kept} kept.")


def flow_list_policies(client: UnifiClient) -> None:
    with _make_progress() as progress:
        t_pol = progress.add_task("Fetching policies...", total=None)
        policies = client.get_policies(progress, t_pol)
    if not policies:
        console.print("[yellow]No policies found.[/yellow]")
        return
    t = Table(title=f"Firewall Policies ({len(policies)})", show_lines=True)
    t.add_column("#", style="dim", width=4)
    t.add_column("Name", style="cyan")
    t.add_column("Action", style="bold")
    t.add_column("Enabled")
    t.add_column("Managed", style="dim")
    t.add_column("Origin", style="dim")
    for i, p in enumerate(policies, 1):
        action = p.get("action", {}).get("type", "?")
        origin = p.get("metadata", {}).get("origin", "?")
        enabled = "[green]yes[/green]" if p.get("enabled") else "[red]no[/red]"
        managed = "[cyan]OK[/cyan]" if TOOL_SIGNATURE in (p.get("description") or "") else ""
        t.add_row(str(i), p.get("name", ""), action, enabled, managed, origin)
    console.print(t)
    tool_count = sum(1 for p in policies if TOOL_SIGNATURE in (p.get("description") or ""))
    if tool_count:
        console.print(f"[dim]{tool_count} policies managed by this tool[/dim]")


def flow_manage_port_lists(client: UnifiClient) -> None:
    while True:
        with _make_progress() as progress:
            t_lists = progress.add_task("Fetching port lists...", total=None)
            all_lists = client.get_traffic_matching_lists()
            progress.update(t_lists, total=len(all_lists), completed=len(all_lists))
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
                    str(item["value"]) if item.get("type") == "PORT_NUMBER"
                    else f"{item['start']}-{item['end']}"
                    for item in l.get("items", [])
                ]
                t.add_row(l["name"], ", ".join(port_strs), l["id"])
            console.print(t)

        elif action == "Create port list":
            name = questionary.text("Port list name:").ask()
            if not name:
                continue
            raw = questionary.text(
                "Ports - comma separated, ranges with hyphen (e.g. 80,443,8000-8080):"
            ).ask()
            if not raw:
                continue

            items: list[dict] = []
            try:
                for part in raw.split(","):
                    part = part.strip()
                    if "-" in part:
                        start, end = part.split("-", 1)
                        items.append({"type": "PORT_NUMBER_RANGE", "start": int(start), "end": int(end)})
                    else:
                        items.append({"type": "PORT_NUMBER", "value": int(part)})
            except ValueError:
                console.print("[red]Invalid port format.[/red]")
                continue

            t = Table(title=f"New port list: {name}", show_lines=True)
            t.add_column("Type")
            t.add_column("Value")
            for item in items:
                if item["type"] == "PORT_NUMBER":
                    t.add_row("Single", str(item["value"]))
                else:
                    t.add_row("Range", f"{item['start']} - {item['end']}")
            console.print(t)

            if not questionary.confirm(f"Create port list '{name}' with {len(items)} entries?").ask():
                continue

            try:
                result = client.create_traffic_matching_list(
                    {"type": "PORTS", "name": name, "items": items}
                )
                console.print(
                    f"[green]Created port list '{name}' (ID: {result.get('id', '?')})[/green]"
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
            if not questionary.confirm(f"Delete '{target['name']}'? This cannot be undone.").ask():
                continue
            try:
                client.delete_traffic_matching_list(target["id"])
                console.print(f"[green]Deleted '{target['name']}'[/green]")
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
