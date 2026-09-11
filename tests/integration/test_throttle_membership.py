import os, platform, pytest
from quota_manager.integration_helpers import _cmd, _has_tools
import quota_manager.quota_management as qm
import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm


@pytest.mark.integration
@pytest.mark.skipif(platform.system() != "Linux", reason="needs Linux")
@pytest.mark.skipif(os.geteuid() != 0, reason="needs root")
@pytest.mark.skipif(not _has_tools("nft"), reason="needs nft")
def test_enforce_quota_throttling_adds_to_throttle_set(monkeypatch):
    pid = os.getpid()
    table = f"qm_test_{pid}"
    throttle_set = "throttle_users"
    drop_set = "drop_users"
    ip = "10.230.1.2"

    def cleanup():
        _cmd(["nft", "delete", "table", "inet", table], check=False)

    cleanup()
    try:
        _cmd(["nft", "add", "table", "inet", table])
        _cmd(
            [
                "nft",
                "add",
                "set",
                "inet",
                table,
                throttle_set,
                "{",
                "type",
                "ipv4_addr",
                ";",
                "}",
            ]
        )
        _cmd(
            [
                "nft",
                "add",
                "set",
                "inet",
                table,
                drop_set,
                "{",
                "type",
                "ipv4_addr",
                ";",
                "}",
            ]
        )

        monkeypatch.setattr(
            qm,
            "throttle_single_user",
            lambda username, user_ip=None: _cmd(
                ["nft", "add", "element", "inet", table, throttle_set, "{", ip, "}"]
            ),
        )
        monkeypatch.setattr(
            qm,
            "drop_single_user",
            lambda username, user_ip=None: _cmd(
                ["nft", "add", "element", "inet", table, drop_set, "{", ip, "}"]
            ),
        )

        # Also patch nft state checks used in enforce
        monkeypatch.setattr(nftm, "check_if_user_throttled", lambda _ip: False)
        monkeypatch.setattr(nftm, "check_if_user_dropped", lambda _ip: False)

        # Patch DB calls inside enforce
        monkeypatch.setattr(
            sqlm, "check_if_user_logged_in", lambda username, db_path=None: True
        )
        monkeypatch.setattr(
            sqlm, "fetch_user_ip_address_usage", lambda username, db_path=None: ip
        )
        monkeypatch.setattr(
            sqlm, "check_if_user_exceeds_quota", lambda username, db_path=None: True
        )

        qm.enforce_quota_single_user("bob", throttling=True, db_path=None)

        out = _cmd(["nft", "list", "set", "inet", table, throttle_set]).stdout
        assert ip in out
        out2 = _cmd(["nft", "list", "set", "inet", table, drop_set]).stdout
        assert ip not in out2
    finally:
        cleanup()
