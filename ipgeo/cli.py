"""CLI entry points for ipgeo."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from ipgeo import __version__
from ipgeo.core import (
    cidr_info,
    geolocate,
    geolocate_batch,
    ip_reputation,
    my_ip,
    reverse_dns,
    validate_ip,
)

console = Console()
err_console = Console(stderr=True)


def _print_json(data) -> None:
    """Emit machine-readable JSON without extra Rich status or progress text."""
    console.print(json.dumps(data, indent=2))


def _json_error(message: str, exit_code: int = 1) -> None:
    """Emit a consistent JSON error payload and exit."""
    _print_json({"error": message})
    sys.exit(exit_code)


def _flag(country_code: str) -> str:
    """Convert ISO 3166-1 alpha-2 code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def _risk_color(level: str) -> str:
    return {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(level, "white")


def _bool_icon(val) -> str:
    return "[green]✓[/green]" if val else "[red]✗[/red]"


def _format_geo_table(data: dict, title: str = "IP Geolocation") -> Table:
    table = Table(title=title, box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Field", style="bold cyan", min_width=20)
    table.add_column("Value", style="white")

    status = data.get("status", "")
    if status == "fail" or "error" in data:
        table.add_row("Error", f"[red]{data.get('message', data.get('error', 'Unknown error'))}[/red]")
        return table

    ip = data.get("query", "")
    country = data.get("country", "")
    cc = data.get("countryCode", "")
    flag = _flag(cc)

    rows = [
        ("IP Address", f"[bold white]{ip}[/bold white]"),
        ("Country", f"{flag} {country} ({cc})" if cc else country),
        ("Region", data.get("regionName", "") or data.get("region", "")),
        ("City", data.get("city", "")),
        ("ZIP / Postal", data.get("zip", "")),
        ("Latitude", str(data.get("lat", ""))),
        ("Longitude", str(data.get("lon", ""))),
        ("Timezone", data.get("timezone", "")),
        ("ISP", data.get("isp", "")),
        ("Organization", data.get("org", "")),
        ("AS Number", data.get("as", "")),
        ("AS Name", data.get("asname", "")),
        ("Reverse DNS", data.get("reverse", "")),
        ("Proxy/VPN", _bool_icon(data.get("proxy", False))),
        ("Hosting/DC", _bool_icon(data.get("hosting", False))),
        ("Mobile", _bool_icon(data.get("mobile", False))),
    ]
    if data.get("queried_host"):
        rows.insert(1, ("Queried Host", data["queried_host"]))
        rows.insert(2, ("Resolved IP", data.get("resolved_ip", ip)))

    for field, value in rows:
        if value and value not in ("", "None", "✗"):
            table.add_row(field, value)
    return table


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="ipgeo")
def cli():
    """ipgeo — IP geolocation and intelligence tool.

    Geolocate IPs, bulk lookup, reverse DNS, CIDR calc, reputation checks.
    """


@cli.command("lookup")
@click.argument("ip_or_host")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def lookup(ip_or_host: str, as_json: bool):
    """Geolocate a single IP address or hostname."""
    with console.status(f"[cyan]Looking up {ip_or_host}…[/cyan]"):
        data = geolocate(ip_or_host)

    if as_json:
        console.print_json(json.dumps(data))
        return

    if data.get("status") == "fail" or "error" in data:
        err_console.print(f"[red]Error:[/red] {data.get('message', data.get('error'))}")
        sys.exit(1)

    table = _format_geo_table(data, title=f"Geolocation — {ip_or_host}")
    console.print(table)

    # Map link
    lat, lon = data.get("lat"), data.get("lon")
    if lat and lon:
        console.print(f"  [dim]Map:[/dim] https://maps.google.com/?q={lat},{lon}")


@cli.command("myip")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def myip_cmd(as_json: bool):
    """Show your own public IP and geolocation."""
    with console.status("[cyan]Detecting your public IP…[/cyan]"):
        data = my_ip()

    if as_json:
        console.print_json(json.dumps(data))
        return

    if data.get("status") == "fail" or "error" in data:
        err_console.print(f"[red]Error:[/red] {data.get('message', data.get('error'))}")
        sys.exit(1)

    table = _format_geo_table(data, title="Your IP Geolocation")
    console.print(table)


@cli.command("bulk")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.option("--csv", "as_csv", is_flag=True, help="Output CSV.")
def bulk(file: str, as_json: bool, as_csv: bool):
    """Bulk geolocate IPs from a file (one per line)."""
    lines = Path(file).read_text().splitlines()
    ips = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]

    if not ips:
        if as_json:
            _json_error("No valid IPs found in file.")
        err_console.print("[red]No valid IPs found in file.[/red]")
        sys.exit(1)

    results = []
    if as_json:
        chunk_size = 100
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i : i + chunk_size]
            chunk_results = geolocate_batch(chunk)
            results.extend(chunk_results)
    else:
        console.print(f"[cyan]Processing {len(ips)} addresses…[/cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Geolocating…", total=len(ips))
            chunk_size = 100
            for i in range(0, len(ips), chunk_size):
                chunk = ips[i : i + chunk_size]
                chunk_results = geolocate_batch(chunk)
                results.extend(chunk_results)
                progress.advance(task, len(chunk))

    if as_json:
        _print_json(results)
        return

    if as_csv:
        cols = ["query", "status", "country", "regionName", "city", "isp", "org", "lat", "lon", "proxy", "hosting"]
        console.print(",".join(cols))
        for r in results:
            row = [str(r.get(c, "")) for c in cols]
            console.print(",".join(row))
        return

    table = Table(title=f"Bulk Geolocation ({len(results)} IPs)", box=box.ROUNDED)
    table.add_column("IP", style="bold cyan", no_wrap=True)
    table.add_column("Country", style="white")
    table.add_column("City", style="white")
    table.add_column("ISP / Org", style="dim", max_width=40)
    table.add_column("Proxy", justify="center")
    table.add_column("Hosting", justify="center")

    for r in results:
        if r.get("status") == "fail":
            table.add_row(r.get("query", ""), "[red]Lookup failed[/red]", "", "", "", "")
            continue
        cc = r.get("countryCode", "")
        flag = _flag(cc)
        country = f"{flag} {r.get('country', '')}" if cc else r.get("country", "")
        city = r.get("city", "")
        org = r.get("isp") or r.get("org") or ""
        proxy = _bool_icon(r.get("proxy", False))
        hosting = _bool_icon(r.get("hosting", False))
        table.add_row(r.get("query", ""), country, city, org, proxy, hosting)

    console.print(table)
    console.print(f"[dim]Processed {len(results)} addresses.[/dim]")


@cli.command("rdns")
@click.argument("ips", nargs=-1, required=True)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def rdns(ips: tuple, as_json: bool):
    """Reverse DNS lookup for one or more IPs."""
    results = []
    if as_json:
        for ip in ips:
            results.append(reverse_dns(ip))
    else:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task("Resolving…", total=len(ips))
            for ip in ips:
                results.append(reverse_dns(ip))
                progress.advance(task)

    if as_json:
        _print_json(results)
        return

    table = Table(title="Reverse DNS Lookup", box=box.ROUNDED)
    table.add_column("IP Address", style="bold cyan", no_wrap=True)
    table.add_column("Hostname", style="white")
    table.add_column("Aliases", style="dim")
    table.add_column("Status", justify="center")

    for r in results:
        hostname = r.get("hostname") or ""
        aliases = ", ".join(r.get("aliases", []))
        if "error" in r and not hostname:
            status = "[red]No PTR[/red]"
        else:
            status = "[green]OK[/green]"
        table.add_row(r["ip"], hostname or "[dim]—[/dim]", aliases or "[dim]—[/dim]", status)

    console.print(table)


@cli.command("cidr")
@click.argument("network")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def cidr_cmd(network: str, as_json: bool):
    """Calculate network details for a CIDR block (e.g. 192.168.1.0/24)."""
    data = cidr_info(network)

    if as_json:
        console.print_json(json.dumps(data))
        return

    if "error" in data:
        err_console.print(f"[red]Error:[/red] {data['error']}")
        sys.exit(1)

    table = Table(title=f"CIDR Info — {data['cidr']}", box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Field", style="bold cyan", min_width=20)
    table.add_column("Value", style="white")

    rows = [
        ("CIDR Block", f"[bold white]{data['cidr']}[/bold white]"),
        ("IP Version", data["version"]),
        ("Network Address", data["network"]),
        ("Broadcast Address", data["broadcast"]),
        ("Subnet Mask", data["netmask"]),
        ("Prefix Length", f"/{data['prefix_len']}"),
        ("Total IPs", f"{data['total_ips']:,}"),
        ("Usable Hosts", f"{data['usable_hosts']:,}"),
        ("First Host", data["first_host"]),
        ("Last Host", data["last_host"]),
        ("Private Range", _bool_icon(data["is_private"])),
        ("Global Range", _bool_icon(data["is_global"])),
        ("Multicast", _bool_icon(data["is_multicast"])),
    ]
    for field, value in rows:
        table.add_row(field, str(value))

    console.print(table)


@cli.command("rep")
@click.argument("ip")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def reputation(ip: str, as_json: bool):
    """Check IP reputation — proxy/VPN/hosting/risk assessment."""
    with console.status(f"[cyan]Checking reputation of {ip}…[/cyan]"):
        data = ip_reputation(ip)

    if as_json:
        console.print_json(json.dumps(data))
        return

    if "error" in data:
        err_console.print(f"[red]Error:[/red] {data['error']}")
        sys.exit(1)

    risk = data["risk_level"]
    risk_color = _risk_color(risk)

    panel_content = (
        f"[bold white]{data['ip']}[/bold white]\n\n"
        f"[cyan]ISP:[/cyan]        {data.get('isp', '—')}\n"
        f"[cyan]Organization:[/cyan] {data.get('org', '—')}\n"
        f"[cyan]Country:[/cyan]    {data.get('country', '—')}\n\n"
        f"[cyan]Is Proxy/VPN:[/cyan]  {_bool_icon(data.get('is_proxy'))}\n"
        f"[cyan]Is Hosting/DC:[/cyan] {_bool_icon(data.get('is_hosting'))}\n"
        f"[cyan]Is Mobile:[/cyan]     {_bool_icon(data.get('is_mobile'))}\n"
    )

    indicators = data.get("threat_indicators", [])
    if indicators:
        panel_content += f"\n[yellow]Threat Indicators:[/yellow]\n"
        for ind in indicators:
            panel_content += f"  [yellow]•[/yellow] {ind}\n"

    panel_content += f"\n[bold {risk_color}]Risk Level: {risk}[/bold {risk_color}]"

    console.print(Panel(panel_content, title="[bold]IP Reputation[/bold]", border_style=risk_color, expand=False))


@cli.command("validate")
@click.argument("ips", nargs=-1, required=True)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def validate_cmd(ips: tuple, as_json: bool):
    """Validate and classify IP addresses (v4/v6, private/public, etc.)."""
    results = [validate_ip(ip) for ip in ips]

    if as_json:
        console.print_json(json.dumps(results))
        return

    table = Table(title="IP Validation", box=box.ROUNDED)
    table.add_column("IP", style="bold cyan", no_wrap=True)
    table.add_column("Valid", justify="center")
    table.add_column("Version", justify="center")
    table.add_column("Private", justify="center")
    table.add_column("Global", justify="center")
    table.add_column("Loopback", justify="center")
    table.add_column("Multicast", justify="center")
    table.add_column("Compressed", style="dim")

    for r in results:
        if not r["valid"]:
            table.add_row(r["ip"], "[red]✗[/red]", "—", "—", "—", "—", "—", f"[red]{r.get('error', '')}[/red]")
            continue
        table.add_row(
            r["ip"],
            "[green]✓[/green]",
            r["version"],
            _bool_icon(r["is_private"]),
            _bool_icon(r["is_global"]),
            _bool_icon(r["is_loopback"]),
            _bool_icon(r["is_multicast"]),
            r["compressed"],
        )

    console.print(table)


@cli.command("range")
@click.argument("start_ip")
@click.argument("end_ip")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def ip_range(start_ip: str, end_ip: str, as_json: bool):
    """Show CIDR blocks that cover a given IP range."""
    import ipaddress as _ip

    try:
        start = _ip.ip_address(start_ip.strip())
        end = _ip.ip_address(end_ip.strip())
    except ValueError as e:
        if as_json:
            _json_error(str(e))
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if start > end:
        if as_json:
            _json_error("start IP must be ≤ end IP")
        err_console.print("[red]Error:[/red] start IP must be ≤ end IP")
        sys.exit(1)

    try:
        networks = list(_ip.summarize_address_range(start, end))
    except Exception as e:
        if as_json:
            _json_error(str(e))
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if as_json:
        _print_json([str(n) for n in networks])
        return

    table = Table(title=f"CIDR Blocks: {start_ip} → {end_ip}", box=box.ROUNDED)
    table.add_column("CIDR Block", style="bold cyan")
    table.add_column("Network", style="white")
    table.add_column("Broadcast", style="white")
    table.add_column("Total IPs", justify="right", style="green")

    total = 0
    for net in networks:
        table.add_row(
            str(net),
            str(net.network_address),
            str(net.broadcast_address),
            f"{net.num_addresses:,}",
        )
        total += net.num_addresses

    console.print(table)
    console.print(f"  [bold]Total:[/bold] {len(networks)} CIDR block(s), {total:,} addresses")
