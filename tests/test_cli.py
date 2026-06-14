from click.testing import CliRunner

from ipgeo.cli import cli


runner = CliRunner()


def test_version_flag_reports_installed_version():
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert "ipgeo, version 0.1.1" in result.output


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
