import pytest
import quota_manager.sql_management as sqlm
import quota_manager.quota_management as qm


def test_ratio_over_1_raises(db_paths):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.6, db_path=usage_db)
    sqlm.create_group_usage("beta", 0.4, db_path=usage_db)

    with pytest.raises(ValueError):
        qm.check_quota_ratio_legality(1.2, group_name="alpha")


def test_ratio_below_0_raises(db_paths):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 1.0, db_path=usage_db)

    with pytest.raises(ValueError):
        qm.check_quota_ratio_legality(-0.01, group_name="alpha")


def test_ratio_min_enforced(db_paths):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.5, db_path=usage_db)

    # set min_quota_ratio to 0.2 via direct SQL (quickest)
    import sqlite3

    con = sqlite3.connect(usage_db)
    con.execute(
        "UPDATE groups SET min_quota_ratio=? WHERE group_name=?", (0.2, "alpha")
    )
    con.commit()
    con.close()

    with pytest.raises(ValueError):
        qm.check_quota_ratio_legality(0.1, group_name="alpha")


def test_ratio_overflow_message_reports_correct_max_allowed(db_paths):
    usage_db, _ = db_paths
    sqlm.create_group_usage("alpha", 0.6, db_path=usage_db)
    sqlm.create_group_usage("beta", 0.4, db_path=usage_db)

    # trying to set alpha to 0.8 while beta=0.4 should cap at 0.6
    with pytest.raises(ValueError) as e:
        qm.check_quota_ratio_legality(0.8, group_name="alpha")

    msg = str(e.value)
    assert "0.6" in msg or "0.600" in msg  # accept minor formatting differences
