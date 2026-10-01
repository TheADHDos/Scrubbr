from datetime import date, datetime, timezone

from app import removal_history


def record(id, **dates):
    return {"id": id, "site_name": "Example", "status": "verified",
            "follow_up_date": "", "recheck_date": "", **dates}


def test_weekly_boundaries_and_confirmed_rechecks():
    rows = [record(1, follow_up_date="2026-09-30"), record(2, follow_up_date="2026-10-01"),
            record(3, recheck_date="2026-10-07", status="confirmed"),
            record(4, recheck_date="2026-10-08"), record(5)]
    groups = removal_history.weekly_actions(rows, date(2026, 10, 1))
    assert [a["record"]["id"] for a in groups["overdue"]] == [1]
    assert [a["record"]["id"] for a in groups["week"]] == [2, 3]


def test_stable_ties_and_one_row_per_scheduled_action():
    rows = [record(2, follow_up_date="2026-10-01"),
            record(1, follow_up_date="2026-10-01", recheck_date="2026-10-01")]
    actions = removal_history.weekly_actions(rows, date(2026, 10, 1))["week"]
    assert [(a["record"]["id"], a["kind"]) for a in actions] == [(1, "follow_up"), (1, "recheck"), (2, "follow_up")]


def test_timezone_boundary_around_utc_midnight():
    now = datetime(2026, 10, 2, 0, 30, tzinfo=timezone.utc)
    assert removal_history.local_today({"app": {"timezone": "America/Los_Angeles"}}, now) == date(2026, 10, 1)
    assert removal_history.local_today({"app": {"timezone": "Asia/Tokyo"}}, now) == date(2026, 10, 2)


def test_empty_queue():
    assert removal_history.weekly_actions([], date(2026, 10, 1)) == {"overdue": [], "week": []}
