from pathlib import Path


def test_analyst_console_contains_investigation_workflow():
    html = (Path(__file__).resolve().parents[2] / "frontend" / "index.html").read_text()
    assert "/api/v1/investigations" in html
    assert "Approve" in html
    assert "Escalate" in html
    assert "Decline" in html
    assert "AI advisory only" in html
