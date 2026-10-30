"""Safety rails: private-target enforcement and lab acknowledgement."""

import pytest

from netguard.attacks import ArpSpoofAttack, SynScanAttack
from netguard.core.safety import (
    SafetyError,
    guard_attack,
    is_private_target,
    require_lab_ack,
    require_private_target,
)


@pytest.mark.parametrize(
    "ip",
    ["192.168.1.1", "10.0.0.5", "172.16.3.4", "127.0.0.1", "169.254.1.1", "fd00::1"],
)
def test_private_targets_allowed(ip):
    assert is_private_target(ip) is True
    require_private_target(ip)  # does not raise


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "example.com", "notanip"])
def test_public_or_invalid_targets_refused(ip):
    assert is_private_target(ip) is False
    with pytest.raises(SafetyError):
        require_private_target(ip)


def test_lab_ack_required():
    with pytest.raises(SafetyError):
        require_lab_ack(False)
    require_lab_ack(True)  # does not raise


def test_guard_attack_combines_checks():
    with pytest.raises(SafetyError):
        guard_attack("8.8.8.8", True)  # public target
    with pytest.raises(SafetyError):
        guard_attack("192.168.1.1", False)  # no lab ack
    guard_attack("192.168.1.1", True)  # ok
    guard_attack(None, True)  # broadcast-domain attack, ack only


def test_attack_refuses_public_target():
    atk = SynScanAttack(target_ip="8.8.8.8", lab_ack=True, dry_run=True)
    with pytest.raises(SafetyError):
        atk.run()


def test_attack_refuses_without_lab_ack():
    atk = ArpSpoofAttack(
        victim_ip="192.168.1.10",
        victim_mac="02:00:00:00:00:0a",
        gateway_ip="192.168.1.1",
        gateway_mac="02:00:00:00:00:01",
        attacker_mac="02:00:00:00:00:66",
        lab_ack=False,
        dry_run=True,
    )
    with pytest.raises(SafetyError):
        atk.run()


def test_attack_dry_run_builds_without_sending():
    atk = ArpSpoofAttack(
        victim_ip="192.168.1.10",
        victim_mac="02:00:00:00:00:0a",
        gateway_ip="192.168.1.1",
        gateway_mac="02:00:00:00:00:01",
        attacker_mac="02:00:00:00:00:66",
        lab_ack=True,
        dry_run=True,
        rounds=2,
    )
    result = atk.run()
    assert result.sent == 0
    assert result.dry_run is True
    assert len(result.packets) == 4  # 2 rounds x 2 directions


def test_attack_respects_max_packets():
    atk = SynScanAttack(
        target_ip="192.168.1.10",
        start_port=1,
        end_port=1000,
        lab_ack=True,
        dry_run=True,
        max_packets=25,
    )
    result = atk.run()
    assert len(result.packets) == 25
