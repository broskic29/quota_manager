import quota_manager.quota_management as qm
import quota_manager.sql_management as sqlm
import quota_manager.nftables_management as nftm


def test_enforce_drop_is_idempotent(monkeypatch):
    calls = {"drop": 0}

    # DB + user state
    monkeypatch.setattr(sqlm, "check_if_user_logged_in", lambda *a, **k: True)
    monkeypatch.setattr(sqlm, "fetch_user_ip_address_usage", lambda *a, **k: "10.0.0.2")
    monkeypatch.setattr(sqlm, "check_if_user_exceeds_quota", lambda *a, **k: True)

    # nft state: first call not dropped, second call dropped
    state = {"dropped": False}
    monkeypatch.setattr(nftm, "check_if_user_throttled", lambda ip: False)
    monkeypatch.setattr(nftm, "check_if_user_dropped", lambda ip: state["dropped"])

    def drop_once(*a, **k):
        calls["drop"] += 1
        state["dropped"] = True

    monkeypatch.setattr(qm, "drop_single_user", drop_once)

    qm.enforce_quota_single_user("bob", throttling=False, db_path=None)
    qm.enforce_quota_single_user("bob", throttling=False, db_path=None)

    assert calls["drop"] == 1, "Drop should only be applied once"
