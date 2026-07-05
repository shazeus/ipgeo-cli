import json

from click.testing import CliRunner

from ipgeo import cli as cli_module
from ipgeo.cli import cli


runner = CliRunner()


def test_version_flag_reports_installed_version():
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert "ipgeo, version 0.1.2" in result.output


def test_validate_json_reports_mixed_addresses():
    result = runner.invoke(cli, ["validate", "192.168.1.1", "::1", "999.1.1.1", "--json"])

    assert result.exit_code == 0
    assert '"valid": true' in result.output
    assert '"valid": false' in result.output
    assert '"version": "IPv4"' in result.output
    assert '"version": "IPv6"' in result.output


def test_range_json_summarizes_expected_blocks():
    result = runner.invoke(cli, ["range", "10.0.0.1", "10.0.0.4", "--json"])

    assert result.exit_code == 0
    assert '"10.0.0.1/32"' in result.output
    assert '"10.0.0.2/31"' in result.output
    assert '"10.0.0.4/32"' in result.output


def test_range_rejects_reverse_bounds():
    result = runner.invoke(cli, ["range", "10.0.0.4", "10.0.0.1"])

    assert result.exit_code != 0
    assert "start IP must be" in result.output


def test_range_json_rejects_reverse_bounds_with_machine_readable_error():
    result = runner.invoke(cli, ["range", "10.0.0.4", "10.0.0.1", "--json"])

    assert result.exit_code != 0
    assert json.loads(result.output) == {"error": "start IP must be ≤ end IP"}


def test_bulk_json_omits_progress_text(monkeypatch, tmp_path):
    input_file = tmp_path / "ips.txt"
    input_file.write_text("8.8.8.8\n1.1.1.1\n", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "geolocate_batch",
        lambda ips: [{"query": ip, "status": "success"} for ip in ips],
    )

    result = runner.invoke(cli, ["bulk", str(input_file), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {"query": "8.8.8.8", "status": "success"},
        {"query": "1.1.1.1", "status": "success"},
    ]


def test_rdns_json_omits_progress_text(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "reverse_dns",
        lambda ip: {"ip": ip, "hostname": f"host-{ip}"},
    )

    result = runner.invoke(cli, ["rdns", "8.8.8.8", "1.1.1.1", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == [
        {"ip": "8.8.8.8", "hostname": "host-8.8.8.8"},
        {"ip": "1.1.1.1", "hostname": "host-1.1.1.1"},
    ]
