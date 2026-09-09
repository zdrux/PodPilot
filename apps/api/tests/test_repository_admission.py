import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from podpilot_api.models import Base, AuditEvent
from podpilot_api.incident_models import IncidentConnection
from podpilot_api.repository_admission import admit_repositories


@pytest.mark.parametrize("can_manage,host,expected", [
    (True, "github.com", "admitted"),
    (False, "github.com", "configuration_admin_required"),
    (True, "untrusted.example", "connector_required"),
])
def test_repository_admission_preserves_host_and_authorization_boundary(can_manage, host, expected):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        connection = IncidentConnection(id="github", kind="github", name="GitHub", enabled=True,
            credential_key="existing-secret-reference", config_json=json.dumps({"url": "https://api.github.com", "repositories": ["org/existing"]}))
        db.add(connection)
        db.commit()
        inventory = {"repositories": [{"url": f"https://{host}/org/discovered", "references": [{"kind": "Application", "uid": "uid"}]}]}
        admit_repositories(db, inventory, actor="ada", cluster_id="cluster", can_manage=can_manage)
        db.commit()
        assert inventory["repositories"][0]["admission"] == expected
        assert connection.credential_key == "existing-secret-reference"
        assert len(json.loads(connection.config_json)["repositories"]) == (2 if expected == "admitted" else 1)
        if expected == "admitted":
            assert db.scalar(select(AuditEvent)).actor == "ada"
            admit_repositories(db, inventory, actor="ada", cluster_id="cluster", can_manage=True)
            assert inventory["repositories"][0]["admission"] == "already_admitted"
    engine.dispose()
