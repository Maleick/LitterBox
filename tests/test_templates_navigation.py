from pathlib import Path


def test_sidebar_includes_remote_credentials_link():
    template_path = Path("/opt/LitterBox/app/templates/base.html")
    template = template_path.read_text(encoding="utf-8")
    assert 'href="/setup/remote-credentials"' in template
    assert "Remote Credentials" in template
