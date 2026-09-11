import quota_manager.quota_management as qm


def test_initialize_session_start_bytes_reads_bytes_even_if_user_is_dropped(
    monkeypatch,
):
    # dropped=True, throttled=False is the edge case that currently returns 0 in your code
    monkeypatch.setattr(qm.nftm, "check_if_user_dropped", lambda ip: True)
    monkeypatch.setattr(qm.nftm, "check_if_user_throttled", lambda ip: False)
    monkeypatch.setattr(qm.nftm, "get_bytes_from_user", lambda ip: 12345)

    baseline = qm.initialize_session_start_bytes("10.0.0.2")
    assert (
        baseline == 12345
    ), "Baseline must reflect current counter to avoid billing the universe"
