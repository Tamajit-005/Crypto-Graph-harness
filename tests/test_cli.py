from typer.testing import CliRunner

from cryptoh.cli import app


def test_version():
    assert CliRunner().invoke(app, ["--version"]).exit_code == 0


def test_list_sources():
    r = CliRunner().invoke(app, ["list", "sources"])
    assert r.exit_code == 0 and "nginx" in r.output


def test_batch_detects_c2():
    r = CliRunner().invoke(app, ["batch", "--source", "data/nginx_c2_attack.log", "--no-mitigate"])
    assert r.exit_code == 0 and "ANOMALY" in r.output
