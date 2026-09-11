def test_root_redirects_to_dashboard_when_logged_in(user_client, db_paths):
    with user_client.session_transaction() as sess:
        sess["username"] = "bob"

    r = user_client.get("/", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/user/bob/dashboard" in r.headers["Location"]


def test_unknown_path_redirects_to_dashboard_when_logged_in(user_client, db_paths):
    with user_client.session_transaction() as sess:
        sess["username"] = "bob"

    r = user_client.get("/refresh", follow_redirects=False)  # or any nonsense path
    assert r.status_code in (302, 303)
    assert "/user/bob/dashboard" in r.headers["Location"]
