from pathlib import Path

from fastapi.testclient import TestClient

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app
from podpilot_api.models import Base
from podpilot_api.settings import Settings

ROOT = Path(__file__).resolve().parents[3]


def test_authenticated_dashboard_and_session(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        cluster_name="test-cluster",
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'podpilot.db'}",
        web_dir=ROOT / "apps" / "web",
        auth_mode="test",
        poc_mode=True,
    )
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    app = create_app(settings, StaticRoleResolver({"ada": Role.APPROVER}))

    with TestClient(app) as client:
        anonymous = client.get("/")
        assert anonymous.status_code == 401

        response = client.get("/", headers={"x-forwarded-user": "ada"})
        assert response.status_code == 200
        assert "Authenticated as ada" in response.text
        assert "Approver permissions resolved" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

        session = client.get("/api/v1/session", headers={"x-forwarded-user": "ada"})
        assert session.json() == {"username": "ada", "role": "approver"}

        ready = client.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready", "database": True}


def test_unknown_and_malformed_users_fail_closed(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'podpilot.db'}",
        web_dir=ROOT / "apps" / "web",
        auth_mode="test",
    )
    app = create_app(settings, StaticRoleResolver({}))

    with TestClient(app) as client:
        assert client.get("/", headers={"x-forwarded-user": "unknown"}).status_code == 403
        assert client.get("/", headers={"x-forwarded-user": "bad user"}).status_code == 401
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").status_code == 503
