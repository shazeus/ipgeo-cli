<p align="center">
  <h1 align="center">ipgeo</h1>
  <p align="center">IP geolocation and intelligence tool for the terminal.</p>
  <p align="center">
    <a href="https://pypi.org/project/ipgeo-cli/"><img src="https://img.shields.io/pypi/v/ipgeo-cli.svg" alt="PyPI"></a>
    <a href="https://pypi.org/project/ipgeo-cli/"><img src="https://img.shields.io/pypi/pyversions/ipgeo-cli.svg" alt="Python"></a>
    <a href="https://github.com/shazeus/ipgeo-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
    <a href="https://github.com/shazeus/ipgeo-cli/stargazers"><img src="https://img.shields.io/github/stars/shazeus/ipgeo-cli.svg" alt="Stars"></a>
  </p>
</p>

---

**ipgeo** is a fast, feature-rich CLI for IP geolocation and network intelligence. Geolocate single IPs or hostnames, run bulk lookups from a file, perform reverse DNS, calculate CIDR networks, check VPN/proxy reputation, and validate IP addresses — all with beautiful rich-powered terminal output.

- **Geolocation** — Country, region, city, coordinates, timezone, ISP, ASN from any IP or hostname
- **Bulk Lookup** — Process hundreds of IPs from a file with progress tracking; export to JSON or CSV
- **Reverse DNS** — PTR record lookups for one or many IPs in a single command
- **CIDR Calculator** — Network address, broadcast, netmask, usable hosts, first/last host
- **IP Range to CIDR** — Summarize any arbitrary IP range into minimal CIDR blocks
- **Reputation Check** — Proxy/VPN/hosting detection and risk scoring
- **IP Validation** — Classify IPs as private/public/loopback/multicast, IPv4 vs IPv6
- **Your IP** — Instantly see your own public IP and geolocation

## Installation

```bash
pip install ipgeo-cli
```

## Usage

```bash
# Look up any IP or hostname
ipgeo lookup 8.8.8.8
ipgeo lookup github.com

# Show your own public IP
ipgeo myip

# Bulk lookup from a file
ipgeo bulk ips.txt
ipgeo bulk ips.txt --csv > results.csv
ipgeo bulk ips.txt --json > results.json

# Reverse DNS
ipgeo rdns 8.8.8.8 1.1.1.1

# CIDR network info
ipgeo cidr 192.168.1.0/24
ipgeo cidr 10.0.0.0/8

# IP range to CIDR blocks
ipgeo range 10.0.0.1 10.0.0.100

# Reputation / VPN / proxy check
ipgeo rep 1.2.3.4

# Validate IP addresses
ipgeo validate 192.168.1.1 ::1 256.0.0.1
```

## Commands

| Command | Description |
|---------|-------------|
| `lookup <ip\|host>` | Geolocate a single IP address or hostname |
| `myip` | Show your public IP and geolocation |
| `bulk <file>` | Bulk geolocate IPs from a text file (one per line) |
| `rdns <ip>…` | Reverse DNS (PTR) lookup for one or more IPs |
| `cidr <network>` | Network details for a CIDR block |
| `range <start> <end>` | Summarize an IP range into CIDR blocks |
| `rep <ip>` | Reputation check — proxy/VPN/hosting/risk level |
| `validate <ip>…` | Validate and classify IP addresses |

All commands support `--json` for machine-readable output.

## Configuration

No API key required. ipgeo uses the free [ip-api.com](http://ip-api.com) service.

For bulk lookups, requests are automatically batched (100 per request) to stay within rate limits.

## License

MIT © [shazeus](https://github.com/shazeus)
