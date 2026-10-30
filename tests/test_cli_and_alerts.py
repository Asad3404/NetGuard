"""CLI smoke tests and Alert serialisation."""

import json

from netguard.cli import main
from netguard.core.alerts import Alert, Evidence


def test_alert_human_and_json_roundtrip():
    a = Alert(
        detector="arp",
        category="arp-spoof",
        severity="high",
        message="binding changed",
        fields={"ip": "192.168.1.1", "new_mac": "02:00:00:00:00:66"},
        evidence=[Evidence(1.0, "ARP is-at", {"op": "is-at"})],
        ts=1767225600.0,
    )
    line = a.human()
    assert "arp/arp-spoof" in line and "HIGH" in line and "192.168.1.1" in line

    obj = json.loads(a.to_json())
    assert obj["detector"] == "arp"
    assert obj["severity"] == "high"
    assert obj["fields"]["ip"] == "192.168.1.1"
    assert obj["evidence"][0]["summary"] == "ARP is-at"


def test_alert_rejects_bad_severity():
    import pytest

    with pytest.raises(ValueError):
        Alert(detector="x", category="y", severity="nope", message="m")


def test_cli_detect_on_sample_returns_nonzero_when_alerts(samples_dir, capsys):
    rc = main(["detect", "--pcap", str(samples_dir / "synscan.pcap")])
    out = capsys.readouterr().out
    assert rc == 1  # alerts present -> exit 1
    assert "tcp-syn-scan" in out


def test_cli_detect_benign_is_clean(samples_dir, capsys):
    rc = main(["detect", "--pcap", str(samples_dir / "benign.pcap")])
    out = capsys.readouterr().out
    assert rc == 0  # no alerts -> exit 0
    assert "0 alert" in out


def test_cli_detect_json_lines(samples_dir, capsys):
    rc = main(["detect", "--pcap", str(samples_dir / "dhcp_rogue.pcap"), "--json"])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 1
    # Every emitted line must be valid JSON.
    objs = [json.loads(line) for line in out]
    assert any(o["category"] == "dhcp-rogue-server" for o in objs)


def test_cli_detect_only_filter(samples_dir, capsys):
    rc = main(["detect", "--pcap", str(samples_dir / "arp_spoof.pcap"), "--only", "dns"])
    out = capsys.readouterr().out
    assert rc == 0  # dns detector sees nothing in an arp capture
    assert "arp-spoof" not in out


def test_cli_replay_alias(samples_dir, capsys):
    rc = main(["replay", str(samples_dir / "dns_spoof.pcap")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "dns-poison-race" in out


def test_cli_attack_refuses_public_target(capsys):
    rc = main([
        "attack", "--i-understand-this-is-a-lab", "synscan",
        "--target-ip", "8.8.8.8",
    ])
    err = capsys.readouterr().err
    assert rc == 3
    assert "REFUSED" in err


def test_cli_attack_refuses_without_ack(capsys):
    rc = main(["attack", "synscan", "--target-ip", "192.168.1.10"])
    err = capsys.readouterr().err
    assert rc == 3
    assert "REFUSED" in err


def test_cli_attack_dry_run_builds(capsys):
    rc = main([
        "attack", "--i-understand-this-is-a-lab", "synscan",
        "--target-ip", "192.168.1.10", "--end-port", "20",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "dry-run" in out
