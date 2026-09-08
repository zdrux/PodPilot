import json
import re
import threading
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func, update
from sqlalchemy.orm import Session
from starlette.requests import Request

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app, SYSTEM_CLUSTER_ID
from podpilot_api.incidents import (
    _activity_result,
    _dedupe_limitations,
    _incident_activity_view,
    _incident_state_version,
    _evidence_limitations,
    _limitation_key,
)
from podpilot_api.models import (
    AdHocConversation, AdHocMessage, AdHocRun, Base, Cluster, ModelProfile,
)
from podpilot_api.incident_models import IncidentConnection, FleetIncident, IncidentRun
from podpilot_api.model_provider import AdHocLogAnalysis, ModelProfileConfig
from podpilot_api.settings import Settings
from podpilot_diagnostics.incidents import IncidentDecision
from podpilot_diagnostics.incident_policy import IncidentPolicy
from podpilot_openshift.incidents import IncidentReader, clean_evidence


class Store:
    def __init__(self): self.values = {}
    def get(self, key=None): return self.values.get(key)
    def set(self, value, key=None): self.values[key] = value
    def delete(self, key=None): self.values.pop(key, None)


def test_activity_view_recovers_complete_specialist_summary_from_evidence():
    full_summary = (
        "Argo CD reports that the application is progressing while the associated Service and "
        "Route are healthy and synced. The out-of-sync Deployment may be linked to the incident onset."
    )
    incident = SimpleNamespace(
        alerts_json=json.dumps({"alert": {"labels": {"alertname": "RolloutFailed"}}}),
        title="Rollout failed", updated_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    )
    run = SimpleNamespace(
        status="partial", created_at=datetime(2026, 9, 6, tzinfo=timezone.utc), completed_at=None,
        activity_json=json.dumps({
            "tasks": [{
                "id": "specialist-1", "role": "specialist", "label": "Argo CD specialist",
                "source": "Argo CD specialist", "state": "completed",
                "work": "Correlate revisions", "result": full_summary[:80],
            }],
            "events": [{
                "at": "2026-09-06T17:27:00Z", "label": "Argo CD specialist",
                "state": "completed", "summary": full_summary[:80],
            }],
        }),
        evidence_json=json.dumps([{
            "id": "E5", "source": "Argo CD specialist",
            "observed_at": "2026-09-06T17:27:00Z", "data": {"summary": full_summary},
        }]),
        briefing_json=json.dumps({
            "problems": ["Revision timing correlates with the rollout failure."],
        }),
    )

    view = _incident_activity_view(incident, run)

    specialist = next(task for task in view["tasks"] if task.get("role") == "specialist")
    assert specialist["result"] == full_summary
    assert view["events"][0]["summary"] == full_summary
    assert view["findings"] == ["Revision timing correlates with the rollout failure."]
    bounded = _activity_result("Argo CD", {"summary": "word " * 200})
    assert len(bounded) <= 600
    assert bounded.endswith("…")


@pytest.fixture
def client(tmp_path):
    settings = Settings(auth_mode="test", data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'incidents.db'}", incidents_enabled=True,
        incident_worker_enabled=False, incident_connector_discovery_enabled=False,
        adhoc_job_worker_enabled=False)
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    cluster_store = Store()
    app = create_app(settings=settings, role_resolver=StaticRoleResolver({
        "sre": Role.INVESTIGATOR, "admin": Role.APPROVER, "viewer": Role.VIEWER,
        "delegated": Role.DELEGATED_OPERATOR}), incident_credential_store=Store(),
        cluster_credential_store=cluster_store)
    with TestClient(app) as client:
        yield client


def admin_headers(client):
    assert client.get('/settings/connectors', headers={'x-forwarded-user':'admin'}).status_code == 200
    return {'x-forwarded-user':'admin', 'x-podpilot-csrf':client.cookies['podpilot_csrf']}


def source(client):
    response = client.post('/api/v1/incident-connections', headers=admin_headers(client), json={
        'kind':'cluster', 'name':'SNO incidents', 'cluster_id':SYSTEM_CLUSTER_ID,
        'enabled':True, 'token':'private-cluster-token', 'webhook_token':'w'*40})
    assert response.status_code == 200, response.text
    return response.json()['id']


def notification(status='firing', starts='2026-09-05T12:00:00Z', name='etcdNoLeader'):
    return {'groupKey':'cluster/etcd', 'status':status, 'alerts':[{
        'status':status, 'labels':{'alertname':name,'severity':'critical'},
        'startsAt':starts, 'fingerprint':'abc', 'annotations':{'summary':'test'}}]}


def send(client, source_id, payload):
    return client.post(f'/api/v1/incident-webhooks/{source_id}', headers={'Authorization':'Bearer '+'w'*40}, json=payload)


def test_webhook_auth_dedupe_resolution_and_recurrence(client):
    sid = source(client)
    assert client.post(f'/api/v1/incident-webhooks/{sid}', json=notification()).status_code == 401
    first = send(client,sid,notification()).json()
    second = send(client,sid,notification()).json()
    assert first['created'] and not second['created']
    send(client,sid,notification('resolved'))
    send(client,sid,notification())  # delayed firing must not reopen
    with Session(client.app.state.engine) as db:
        assert db.get(FleetIncident,first['incident_id']).alert_state == 'resolved'
        assert db.scalar(select(func.count()).select_from(IncidentRun)) == 1
    third = send(client,sid,notification(starts='2026-09-05T13:00:00Z')).json()
    assert third['incident_id'] != first['incident_id']
    assert third['created']


def test_alert_policy_and_truncation(client):
    sid = source(client)
    assert send(client,sid,notification(name='KubeJobNotCompleted')).json()['accepted'] == 0
    body = notification(); body['alerts'][0]['labels']['severity']='warning'
    assert send(client,sid,body).json()['accepted'] == 0
    body = notification(); body['truncatedAlerts']=4
    result = send(client,sid,body).json()
    page = client.get('/incidents/'+result['incident_id'],headers={'x-forwarded-user':'sre'})
    assert page.status_code == 200
    assert 'truncated' in page.text


def test_cluster_connector_accepts_custom_alert_names(client):
    sid = source(client)
    response = client.post('/api/v1/incident-connections', headers=admin_headers(client), json={
        'id': sid, 'kind': 'cluster', 'name': 'SNO incidents',
        'cluster_id': SYSTEM_CLUSTER_ID, 'enabled': True,
        'allowed_alerts': ['GitOpsRolloutFailed', 'GitOpsRolloutFailed'],
    })
    assert response.status_code == 200, response.text
    assert send(client, sid, notification(name='etcdNoLeader')).json()['accepted'] == 0
    assert send(client, sid, notification(name='GitOpsRolloutFailed')).json()['accepted'] == 1
    with Session(client.app.state.engine) as db:
        row = db.get(IncidentConnection, sid)
        assert json.loads(row.config_json)['allowed_alerts'] == ['GitOpsRolloutFailed']


def test_cluster_connector_rejects_invalid_alert_names(client):
    sid = source(client)
    response = client.post('/api/v1/incident-connections', headers=admin_headers(client), json={
        'id': sid, 'kind': 'cluster', 'name': 'SNO incidents',
        'cluster_id': SYSTEM_CLUSTER_ID, 'enabled': True,
        'allowed_alerts': ['../../namespaces/customer'],
    })
    assert response.status_code == 422
    assert 'valid Prometheus alert name' in response.text


def test_incident_detail_groups_alerts_formats_briefing_and_links_evidence(client):
    sid = source(client)
    iid = send(client, sid, notification()).json()['incident_id']
    repeated = notification()['alerts'][0]
    with Session(client.app.state.engine) as db:
        incident = db.get(FleetIncident, iid)
        incident.alerts_json = json.dumps({f'fingerprint-{index}': repeated for index in range(3)})
        run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == iid))
        run.status = 'completed'
        run.briefing_json = json.dumps({
            'summary': (
                'The **API server is healthy** based on Evidence E1. '
                'A dependent workload remains unavailable.'
            ),
            'hypotheses': [
                '1. **Synthetic signal** - verify the simulation label.\n\n'
                '| Evidence | Observation |\n|---|---|\n'
                '| E1 | `restartCount=9` |',
            ],
            'evidence_ids': ['E1'],
            'next_steps': ['- Confirm the alert rule source.'],
            'limitations': ['Only a bounded snapshot was collected.', 'A distinct inference remains uncertain.'],
            'system_limitations': ['Only a bounded snapshot was collected.'],
            'model_limitations': ['A distinct inference remains uncertain.'],
        })
        run.evidence_json = json.dumps([{
            'id': 'E1', 'source': 'operators', 'observed_at': '2026-09-05T12:01:00Z',
            'data': {'rows': [{'name': 'kube-apiserver', 'available': True}]},
        }])
        run_id = run.id
        db.commit()

    page = client.get(f'/incidents/{iid}', headers={'x-forwarded-user':'sre'})

    assert page.status_code == 200
    assert 'data-investigation-active="false"' in page.text
    assert 'data-state-version="' in page.text
    assert 'data-live-status' not in page.text
    assert 'role="tablist"' in page.text
    assert 'incident-panel-overview' not in page.text
    assert '>Overview</button>' not in page.text
    assert f'aria-selected="true" data-incident-tab="incident-panel-run-{run_id}"' in page.text
    assert f'data-incident-tab-panel>\n    <dl class="incident-ledger-summary"' in page.text
    assert 'incident-tab-activity' not in page.text
    assert '<h2>Assessment findings</h2>' in page.text
    assert '<strong>API server is healthy</strong>' in page.text
    assert '**API server is healthy**' not in page.text
    assert 'Problems found:' not in page.text
    problems = re.search(
        r'<ol class="incident-ledger-findings">(.*?)</ol>', page.text, re.DOTALL,
    ).group(1)
    assert problems.count('<li>') == 2
    assert '<dt>Alert</dt><dd title="etcdNoLeader">etcdNoLeader</dd>' in page.text
    assert '<dt>Alert state</dt><dd>Firing</dd>' in page.text
    assert 'data-evidence-link' in page.text
    assert f'href="#evidence-{run_id}-E1"' in page.text
    assert f'id="evidence-{run_id}-E1"' in page.text
    assert 'class="incident-ledger-summary"' in page.text
    assert '<button type="button" class="incident-ledger-evidence"' in page.text
    assert '<details class="incident-ledger-evidence"' not in page.text
    assert '<h2>Assessment findings</h2>' in page.text
    assert '<h2>Evidence ledger</h2>' in page.text
    assert '<h2>Investigation activity</h2>' in page.text
    assert 'class="incident-run-task incident-run-task-' in page.text
    assert 'data-incident-detail-open-id="task-' in page.text
    assert '<dt>Activity</dt>' in page.text
    assert '<strong>Result</strong>' in page.text
    assert f'data-incident-evidence-open="evidence-dialog-{run_id}-E1"' in page.text
    assert f'id="evidence-dialog-{run_id}-E1"' in page.text
    assert 'class="incident-evidence-dialog-objects"' in page.text
    assert 'Retained payload' in page.text
    assert 'Recommendations only. No changes have been made.' in page.text
    assert 'Observed objects' in page.text
    assert 'kube-apiserver' in page.text
    assert 'class="incident-inline-citation"' in page.text
    assert 'class="panel incident-panel"' not in page.text
    assert '>- Confirm' not in page.text
    ranked_hypotheses = re.search(
        r'<ol class="incident-ledger-hypotheses">(.*?)</ol>', page.text, re.DOTALL,
    ).group(1)
    assert '<table>' not in ranked_hypotheses
    assert '<code>restartCount=9</code>' in ranked_hypotheses
    assert 'Collection and policy limits' in page.text
    assert f'data-incident-detail-open-id="limits-{run_id}-system"' in page.text
    assert 'Model-reported uncertainty' in page.text
    assert 'A distinct inference remains uncertain.' in page.text

    script = (Path(__file__).parents[2] / 'web/static/incidents.js').read_text(encoding='utf-8')
    assert "target.open = true" not in script
    assert "target.dataset.incidentEvidenceOpen" in script
    assert "dialog.showModal()" in script
    assert "replacement.dataset.stateVersion !== incidentDetail.dataset.stateVersion" in script
    assert "restoreOpen(incidentDetail, 'data-incident-detail-open-id', expandedDetails)" in script
    assert "incidentDetail.dataset.investigationActive === 'true'" in script
    styles = (Path(__file__).parents[2] / 'web/static/styles.css').read_text(encoding='utf-8')
    assert '.incident-next-steps > li {' in styles
    assert '.incident-next-steps li {' not in styles
    assert '.incident-ledger-section .incident-markdown { color: var(--theme-muted); font-size: 13px;' in styles
    assert '.incident-ledger-summary dd { margin: 0; overflow: hidden; color: var(--theme-text); font-size: 13px;' in styles
    assert '.incident-run-task > summary { display: grid;' in styles
    assert '\n.incident-activity-columns, .incident-activity-row { display: grid;' not in styles
    assert "target.scrollIntoView" in script
    assert "new EventSource" in script
    assert f'data-events-url="/api/v1/incidents/{iid}/events"' in page.text
    assert 'Progress will appear here automatically.' not in page.text


def test_incident_live_version_tracks_orchestrator_progress(client):
    sid = source(client)
    iid = send(client, sid, notification()).json()['incident_id']
    with Session(client.app.state.engine) as db:
        initial = _incident_state_version(db, incident_id=iid)
        run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == iid))
        run.status = 'running'
        run.activity_json = json.dumps({
            'phase': 'Collecting evidence',
            'current_work': 'Checking cluster operators',
            'updated_at': '2026-09-05T12:02:00Z',
            'tasks': [],
            'events': [],
        })
        db.commit()
    with Session(client.app.state.engine) as db:
        progressed = _incident_state_version(db, incident_id=iid)
        board_progressed = _incident_state_version(db)
    assert progressed != initial
    assert board_progressed == progressed
    page = client.get(f'/incidents/{iid}', headers={'x-forwarded-user': 'sre'})
    assert 'data-investigation-active="true"' in page.text
    assert 'data-live-status' in page.text
    assert 'incident-title-live-pulse' in page.text
    assert 'incident-tab-live-pulse' in page.text
    assert 'aria-label="Investigation in progress"' in page.text


def test_incident_live_streams_require_incident_access(client):
    paths = ('/api/v1/incidents/events', '/api/v1/incidents/missing/events')
    for path in paths:
        assert client.get(path, headers={'x-forwarded-user': 'viewer'}).status_code == 403


def test_incident_live_stream_emits_opaque_state_version(client):
    sid = source(client)
    send(client, sid, notification())
    route = next(route for route in client.app.routes if route.path == '/api/v1/incidents/events')

    async def first_event():
        async def receive():
            return {'type': 'http.request', 'body': b'', 'more_body': False}

        request = Request({
            'type': 'http', 'method': 'GET', 'path': route.path,
            'headers': [], 'query_string': b'',
        }, receive=receive)
        response = await route.endpoint(
            request=request, user=SimpleNamespace(role=Role.INVESTIGATOR),
        )
        event = await anext(response.body_iterator)
        await response.body_iterator.aclose()
        return response, event

    response, event = asyncio.run(first_event())
    assert response.media_type == 'text/event-stream'
    assert response.headers['cache-control'] == 'no-cache, no-store'
    assert response.headers['x-accel-buffering'] == 'no'
    assert 'event: update' in event
    assert '"version"' in event
    assert 'operators' not in event


def test_incident_dashboard_pins_active_runs_and_expands_live_activity(client):
    sid = source(client)
    active_id = send(client, sid, notification()).json()['incident_id']
    historical_payload = notification(starts='2026-09-05T13:00:00Z')
    historical_payload['groupKey'] = 'cluster/historical'
    historical_payload['alerts'][0]['fingerprint'] = 'historical'
    historical_id = send(client, sid, historical_payload).json()['incident_id']
    with Session(client.app.state.engine) as db:
        active_run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == active_id))
        active_run.status = 'running'
        active_run.evidence_json = json.dumps([{
            'id': 'E1', 'source': 'operators', 'observed_at': '2026-09-05T12:01:00Z',
            'data': {'rows': [{'name': 'kube-apiserver'}]},
        }])
        active_run.activity_json = json.dumps({
            'phase': 'Specialist analysis', 'current_work': 'Waiting for platform log specialists',
            'updated_at': '2026-09-05T12:02:00Z', 'tasks': [
                {'id': 'coordinator', 'role': 'coordinator', 'label': 'Incident coordinator',
                 'state': 'running', 'work': 'Correlating current evidence',
                 'started_at': '2026-09-05T12:00:01Z', 'ended_at': None, 'result': ''},
                {'id': 's1', 'role': 'specialist', 'label': 'Pod log specialist',
                 'state': 'running', 'work': 'Analyzing kube-apiserver logs',
                 'started_at': '2026-09-05T12:01:00Z', 'ended_at': None, 'result': ''},
                {'id': 's2', 'role': 'specialist', 'label': 'Argo CD specialist',
                 'state': 'queued', 'work': 'Reviewing platform deployment history',
                 'started_at': None, 'ended_at': None, 'result': ''},
                {'id': 's3', 'role': 'specialist', 'label': 'GitHub specialist',
                 'state': 'completed', 'work': 'Reviewing revision metadata',
                 'started_at': '2026-09-05T12:00:10Z', 'ended_at': '2026-09-05T12:00:20Z',
                 'result': 'No related platform PR was found.'},
                {'id': 's4', 'role': 'specialist', 'label': 'Route specialist',
                 'state': 'error', 'work': 'Checking route state',
                 'started_at': '2026-09-05T12:00:10Z', 'ended_at': '2026-09-05T12:00:15Z',
                 'result': '<script>unsafe</script>'},
                {'id': 's5', 'role': 'specialist', 'label': 'Deployment specialist',
                 'state': 'stopped', 'work': 'Reviewing deployment state',
                 'started_at': '2026-09-05T12:00:10Z', 'ended_at': '2026-09-05T12:00:15Z',
                 'result': 'Stopped when the incident worker restarted.'},
            ], 'events': [
                {'at': '2026-09-05T12:01:30Z', 'label': 'Coordinator',
                 'state': 'running', 'summary': 'Requested bounded platform log analysis.'},
            ],
        })
        active_run.briefing_json = json.dumps({
            'problems': ['The affected pod remains pending based on E6.'],
        })
        historical_run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == historical_id))
        historical_run.status = 'completed'
        historical_run.completed_at = datetime(2026, 9, 5, 13, 3, tzinfo=timezone.utc)
        db.commit()

    page = client.get('/incidents', headers={'x-forwarded-user': 'sre'})

    assert page.status_code == 200
    assert 'data-active-incidents="1"' in page.text
    assert 'incident-dashboard-stats' not in page.text
    assert 'incident-dashboard-filter' not in page.text
    assert 'Monitor critical OpenShift alerts' not in page.text
    assert 'Fleet history' not in page.text
    assert 'All other investigations' not in page.text
    dashboard = page.text[page.text.index('data-incident-dashboard'):]
    assert dashboard.index(active_id) < dashboard.index(historical_id)
    assert 'Waiting for platform log specialists' in page.text
    assert page.text.index('The affected pod remains pending based on E6.') < page.text.index('Workstream')
    assert 'class="incident-activity-findings"' in page.text
    assert '1 active' in page.text and '1 queued · 1 done · 2 error' in page.text
    for state in ('running', 'queued', 'completed', 'error', 'stopped'):
        assert f'incident-activity-mark-{state}' in page.text
    assert 'Analyzing kube-apiserver logs' in page.text
    assert 'Requested bounded platform log analysis.' not in page.text
    assert 'Recent transitions' not in page.text
    assert 'Activity journal' not in page.text
    assert 'No related platform PR was found.' in page.text
    assert 'The PodPilot incident worker restarted before this task finished.' in page.text
    assert 'Stopped when the incident worker restarted.' not in page.text
    assert '&lt;script&gt;unsafe&lt;/script&gt;' in page.text
    assert '<script>unsafe</script>' not in page.text
    assert page.text.count('incident-live-pulse') >= 2
    assert 'incident-row-live-pulse' in page.text
    assert page.text.count('Open full investigation') == 2
    assert page.text.count('class="incident-row-open-case"') == 2
    assert 'incident-list-findings-1' in page.text
    assert 'data-events-url="/api/v1/incidents/events"' in page.text
    assert 'class="incident-board-table-header" role="row"' in page.text


def test_connections_secret_isolation_and_access(client):
    sid = source(client)
    with Session(client.app.state.engine) as db:
        row = db.get(IncidentConnection,sid)
        assert 'private-cluster-token' not in row.config_json
    page = client.get('/settings/connectors?edit='+sid,headers={'x-forwarded-user':'admin'})
    assert 'private-cluster-token' not in page.text and 'w'*40 not in page.text
    for who in ('viewer','delegated'):
        assert client.get('/incidents',headers={'x-forwarded-user':who}).status_code == 403
    assert client.get('/settings/connectors',headers={'x-forwarded-user':'sre'}).status_code == 403
    assert client.post('/api/v1/incident-connections',headers={'x-forwarded-user':'admin'},json={}).status_code == 403


def test_connector_directory_groups_independent_types_and_uses_type_chooser(client):
    source(client)
    headers=admin_headers(client)
    assert client.post('/api/v1/incident-connections',headers=headers,json={
        'kind':'argocd','name':'Central GitOps','enabled':True,'url':'https://argocd.example',
        'token':'argocd-read-token','projects':['platform']}).status_code==200
    assert client.post('/api/v1/incident-connections',headers=headers,json={
        'kind':'github','name':'Corporate GitHub','enabled':True,'url':'https://github.example',
        'token':'github-read-token','repositories':['platform/config']}).status_code==200
    page=client.get('/settings/connectors',headers={'x-forwarded-user':'admin'})
    assert page.status_code == 200
    assert 'aria-label="Connector instances"' in page.text
    assert all(f'id="nav-connector-group-{kind}"' in page.text for kind in ('cluster','github','argocd'))
    assert 'Central GitOps' in page.text and 'Corporate GitHub' in page.text
    assert 'aria-label="Configured connectors"' not in page.text
    chooser=client.get('/settings/connectors?new=1',headers={'x-forwarded-user':'admin'})
    assert 'Choose a connector type' in chooser.text
    assert '/settings/clusters?new=1&amp;connector=1' in chooser.text
    assert '/settings/connectors?new=1&amp;type=argocd' in chooser.text
    assert '/settings/connectors?new=1&amp;type=github' in chooser.text
    cluster_setup=client.get('/settings/clusters?new=1&connector=1',headers={'x-forwarded-user':'admin'})
    assert 'data-redirect-template="/settings/connectors?new=1&amp;type=cluster&amp;cluster_id={cluster_id}"' in cluster_setup.text


def test_rerun_keeps_history_and_rejects_duplicates(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    headers=admin_headers(client)
    assert client.post(f'/api/v1/incidents/{iid}/rerun',headers=headers).status_code==409
    with Session(client.app.state.engine) as db:
        run=db.scalar(select(IncidentRun)); run.status='completed'; db.commit()
    assert client.post(f'/api/v1/incidents/{iid}/rerun',headers=headers).status_code==200
    with Session(client.app.state.engine) as db:
        assert db.scalar(select(func.count()).select_from(IncidentRun))==2


def test_worker_model_selection_rejects_out_of_scope_reads(client):
    sid=source(client); send(client,sid,notification())
    service=client.app.state.incident_service
    calls=[]
    class Reader:
        def collect(self,key): calls.append(key); return {'rows':[]}
        def catalog(self): return {'operators':'Operators','nodes':'Node health'}
        def close(self): pass
    service.cluster_reader=lambda *args:Reader()
    from podpilot_api.model_provider import ModelProfileConfig
    service.model_context=lambda engine:(ModelProfileConfig(provider_label='test',base_url='https://model.invalid',chat_model='test',embedding_model=None,timeout_seconds=30,max_output_tokens=2000),'model-secret')
    class Provider:
        def __init__(self): self.steps=0
        def incident_step(self,*args):
            self.steps+=1
            if self.steps==1: return IncidentDecision(collect=['pods:user-app','nodes'])
            return IncidentDecision(summary='No cause confirmed.', evidence_ids=['E1','E2','E3'],next_steps=['Check control-plane availability.'])
    service.provider=Provider()
    with Session(client.app.state.engine) as db: rid=db.scalar(select(IncidentRun.id))
    service.investigate(client.app.state.engine,rid)
    assert calls==['operators','nodes']
    with Session(client.app.state.engine) as db:
        run=db.get(IncidentRun,rid)
        assert run.status=='completed'
        assert 'request rejected' in run.briefing_json
        assert 'model-secret' not in run.briefing_json


def test_worker_scopes_namespaced_collectors_from_admitted_alert_labels(client):
    sid = source(client)
    body = notification()
    body['alerts'][0]['labels']['namespace'] = 'team-checkout'
    iid = send(client, sid, body).json()['incident_id']
    service = client.app.state.incident_service
    observed_scopes = []

    class Reader:
        def collect(self, _key):
            return {'rows': []}

        def catalog(self):
            return {'operators': 'Operators'}

        def close(self):
            pass

    def scoped_reader(_cluster, _token, namespaces=(), *policy_args):
        observed_scopes.append(tuple(namespaces))
        return Reader()

    service.cluster_reader = scoped_reader
    service.model_context = lambda _engine: (None, None)
    with Session(client.app.state.engine) as db:
        run_id = db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id == iid))

    service.investigate(client.app.state.engine, run_id)

    assert observed_scopes == [('team-checkout',)]


def test_worker_partitions_large_evidence_before_specialists(client):
    sid = source(client)
    iid = send(client, sid, notification()).json()['incident_id']
    service = client.app.state.incident_service
    rows = [{'name': f'operator-{i}', 'message': 'observed failure ' * 80} for i in range(150)]
    received = []

    class Reader:
        def collect(self, key):
            return {'rows': rows if key == 'operators' else []}

        def catalog(self):
            return {'operators': 'Operators'}

        def close(self):
            pass

    class Provider:
        def incident_step(self, config, _key, context):
            assert config.max_input_tokens == 4000
            assert config.max_output_tokens == 2000
            if context.get('specialist') == 'Evidence':
                received.extend(context['evidence'][0]['data']['rows'])
            return IncidentDecision(summary='Observed failure',
                evidence_ids=[item['id'] for item in context['evidence']])

    service.cluster_reader = lambda *_args: Reader()
    service.model_context = lambda _engine: (ModelProfileConfig(
        provider_label='test', base_url='https://model.invalid', chat_model='test',
        embedding_model=None, timeout_seconds=30, max_input_tokens=4000,
        max_output_tokens=2000), 'model-secret')
    service.provider = Provider()
    with Session(client.app.state.engine) as db:
        run_id = db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id == iid))
    service.investigate(client.app.state.engine, run_id)
    assert received == rows
    with Session(client.app.state.engine) as db:
        run = db.get(IncidentRun, run_id)
        retained = json.loads(run.evidence_json)
        assert next(item for item in retained if item['source'] == 'operators')['data']['rows'] == rows
        assert len([item for item in retained if item['source'] == 'Evidence specialist']) > 1


def test_incident_uses_coordinator_turns_as_its_primary_budget(client):
    sid = source(client)
    iid = send(client, sid, notification()).json()['incident_id']
    service = client.app.state.incident_service

    class Reader:
        def collect(self, key):
            return {'rows': []}

        def catalog(self):
            return {'operators': 'Operators', 'nodes': 'Node health'}

        def close(self):
            pass

    class Provider:
        def incident_step(self, *_args):
            return IncidentDecision(collect=['nodes'])

    service.cluster_reader = lambda *_args: Reader()
    service.model_context = lambda _engine: (
        ModelProfileConfig(
            provider_label='test', base_url='https://model.invalid', chat_model='test',
            embedding_model=None, timeout_seconds=30, max_output_tokens=2000,
            incident_policy=IncidentPolicy(max_rounds=2),
        ),
        'model-secret',
    )
    service.provider = Provider()
    with Session(client.app.state.engine) as db:
        run_id = db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id == iid))

    service.investigate(client.app.state.engine, run_id)

    with Session(client.app.state.engine) as db:
        run = db.get(IncidentRun, run_id)
        assert run.status == 'budget_exhausted'
        briefing = json.loads(run.briefing_json)
        assert 'Coordinator turn budget reached after 2 investigation rounds.' in briefing['limitations']
        assert 'Investigation time budget reached.' not in briefing['limitations']
        assert 'Read time budget reached.' not in briefing['limitations']
        activity = json.loads(run.activity_json)
        planning = [
            event['summary'] for event in activity['events']
            if str(event.get('summary', '')).startswith('Planning investigation round ')
        ]
        assert planning == [
            'Planning investigation round 1 (max 2)',
            'Planning investigation round 2 (max 2)',
        ]


def test_incident_log_specialist_keeps_raw_logs_out_of_coordinator_context(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    service=client.app.state.incident_service
    contexts=[]
    retry_budgets=[]
    class Reader:
        exposed=False
        def collect(self,key):
            if key=='pods:openshift-etcd': self.exposed=True; return {'rows':[{'name':'etcd-0'}]}
            if key=='logs:exact': return {'namespace':'openshift-etcd','pod':'etcd-0',
                'container':'etcd','logs':'sensitive bounded log excerpt'}
            return {'rows':[]}
        def catalog(self):
            result={'operators':'Operators','pods:openshift-etcd':'Etcd Pods'}
            if self.exposed: result['logs:exact']='Observed etcd container logs'
            return result
        def close(self): pass
    class Provider:
        def incident_step(self,_profile,_key,context):
            retry_budgets.append((_profile.max_retries, _profile.timeout_seconds))
            contexts.append(context)
            coordinator_calls=[item for item in contexts if 'specialist' not in item]
            if len(coordinator_calls)==1: return IncidentDecision(collect=['pods:openshift-etcd'])
            if len(coordinator_calls)==2: return IncidentDecision(collect=['logs:exact'])
            return IncidentDecision(summary='Log specialist found no incident anomaly.',evidence_ids=['E5'])
        def analyze_logs(self,_profile,_key,context):
            retry_budgets.append((_profile.max_retries, _profile.timeout_seconds))
            assert context['logs'][0]['evidence_id']=='E4'
            return AdHocLogAnalysis(overview='No meaningful anomaly identified.',issues=[],limitations=[])
    service.cluster_reader=lambda *args:Reader()
    service.model_context=lambda engine:(ModelProfileConfig(provider_label='test',base_url='https://model.invalid',
        chat_model='test',embedding_model=None,timeout_seconds=30,max_output_tokens=2000),'model-secret')
    service.provider=Provider()
    with Session(client.app.state.engine) as db: rid=db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id==iid))
    service.investigate(client.app.state.engine,rid)
    coordinator=[item for item in contexts if 'specialist' not in item]
    assert all('sensitive bounded log excerpt' not in json.dumps(item) for item in coordinator)
    assert any(e['source']=='Pod log specialist' for e in coordinator[-1]['evidence'])
    with Session(client.app.state.engine) as db:
        run=db.get(IncidentRun,rid)
        retained=json.loads(run.evidence_json)
        assert any(e['source']=='logs:exact' for e in retained)
        assert run.status=='completed'
        activity=json.loads(run.activity_json)
        specialist=next(item for item in activity['tasks'] if item.get('role')=='specialist')
        assert specialist['state']=='completed'
        assert specialist['started_at'] and specialist['ended_at']
        assert 'Analyze bounded incident logs' in specialist['work']
        assert specialist['result']=='No meaningful anomaly identified.'
        assert any(
            str(event.get('summary')).startswith('Planning investigation round ')
            and str(event.get('summary')).endswith('(max 10)')
            for event in activity['events']
        )
        assert retry_budgets
        assert all(retries == 3 for retries, _timeout in retry_budgets)
        assert all(1 <= timeout <= 90 for _retries, timeout in retry_budgets)


def test_connector_specialist_isolated_from_coordinator_context(client):
    sid=source(client)
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'Platform GitOps','enabled':True,
        'url':'https://argocd.example','token':'argocd-read-token','projects':['platform']})
    assert response.status_code==200
    iid=send(client,sid,notification()).json()['incident_id']
    service=client.app.state.incident_service
    contexts=[]
    class Reader:
        monitor=None
        def collect(self,key): return {'rows':[]}
        def catalog(self): return {'operators':'Operators'}
        def argocd(self,*args): return {'changes':[], 'partial':False}
        def close(self): pass
    class Provider:
        def incident_step(self,_profile,_key,context):
            contexts.append(context)
            if context.get('specialist')=='Argo CD':
                return IncidentDecision(summary='No nearby platform deployment.',
                    evidence_ids=[context['evidence'][0]['id']])
            return IncidentDecision(summary='No deployment correlation.',evidence_ids=['E4'])
    service.cluster_reader=lambda *args:Reader()
    service.reader_factory=lambda *args,**kwargs:Reader()
    service.model_context=lambda engine:(ModelProfileConfig(provider_label='test',base_url='https://model.invalid',
        chat_model='test',embedding_model=None,timeout_seconds=30,max_output_tokens=2000),'model-secret')
    service.provider=Provider()
    with Session(client.app.state.engine) as db: rid=db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id==iid))
    service.investigate(client.app.state.engine,rid)
    coordinator=next(item for item in contexts if not item.get('specialist'))
    assert not any(e['source'].startswith('Argo CD:') for e in coordinator['evidence'])
    assert any(e['source']=='Argo CD specialist' for e in coordinator['evidence'])
    with Session(client.app.state.engine) as db:
        retained=json.loads(db.get(IncidentRun,rid).evidence_json)
        assert any(e['source'].startswith('Argo CD:') for e in retained)


def test_log_specialists_fan_out_in_parallel(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    service=client.app.state.incident_service
    barrier=threading.Barrier(3); threads=set(); lock=threading.Lock()
    class Reader:
        exposed=False
        def collect(self,key):
            if key=='pods:openshift-etcd': self.exposed=True; return {'rows':[{'name':'etcd-0'}]}
            if key.startswith('logs:'): return {'namespace':'openshift-etcd','pod':'etcd-0',
                'container':key,'logs':'bounded log'}
            return {'rows':[]}
        def catalog(self):
            result={'operators':'Operators','pods:openshift-etcd':'Etcd Pods'}
            if self.exposed: result.update({f'logs:{i}':f'Log {i}' for i in range(3)})
            return result
        def close(self): pass
    class Provider:
        calls=0
        def incident_step(self,*args):
            self.calls+=1
            if self.calls==1: return IncidentDecision(collect=['pods:openshift-etcd'])
            if self.calls==2: return IncidentDecision(collect=['logs:0','logs:1','logs:2'])
            return IncidentDecision(summary='Parallel specialists completed.',evidence_ids=['E7'])
        def analyze_logs(self,*args):
            with lock: threads.add(threading.get_ident())
            barrier.wait(timeout=2)
            return AdHocLogAnalysis(overview='No meaningful anomaly identified.',issues=[],limitations=[])
    service.cluster_reader=lambda *args:Reader()
    service.model_context=lambda engine:(ModelProfileConfig(provider_label='test',base_url='https://model.invalid',
        chat_model='test',embedding_model=None,timeout_seconds=30,max_output_tokens=2000),'model-secret')
    service.provider=Provider()
    with Session(client.app.state.engine) as db: rid=db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id==iid))
    service.investigate(client.app.state.engine,rid)
    assert len(threads)==3
    with Session(client.app.state.engine) as db:
        evidence=json.loads(db.get(IncidentRun,rid).evidence_json)
        assert sum(e['source']=='Pod log specialist' for e in evidence)==3


def test_previous_and_loki_logs_are_isolated_to_specialists(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    service=client.app.state.incident_service
    coordinator_contexts=[]
    class Reader:
        exposed=False
        def collect(self,key):
            if key=='operators': return {'rows':[]}
            if key=='pods:openshift-etcd':
                self.exposed=True
                return {'rows':[{'name':'etcd-0'}]}
            if key.startswith('logs-previous:'):
                return {'namespace':'openshift-etcd','pod':'etcd-0','container':'etcd',
                    'mechanism':'kubernetes-pod-log','logs':'private previous crash log'}
            if key.startswith('loki-logs:'):
                return {'namespace':'openshift-etcd','pod':'etcd-0','container':'etcd',
                    'mechanism':'loki-infrastructure-query','logs':'private historical log'}
            return {'rows':[]}
        def catalog(self):
            result={'operators':'Operators','pods:openshift-etcd':'Etcd Pods'}
            if self.exposed:
                result.update({'logs-previous:a':'Previous logs','loki-logs:a':'Loki history'})
            return result
        def close(self): pass
    class Provider:
        calls=0
        def incident_step(self,_profile,_key,context):
            coordinator_contexts.append(context)
            self.calls+=1
            if self.calls==1: return IncidentDecision(collect=['pods:openshift-etcd'])
            if self.calls==2: return IncidentDecision(collect=['logs-previous:a','loki-logs:a'])
            return IncidentDecision(summary='Specialists reviewed crash history.',evidence_ids=['E6','E7'])
        def analyze_logs(self,_profile,_key,context):
            assert len(context['logs'])==1
            return AdHocLogAnalysis(overview='Crash evidence reviewed.',issues=[],limitations=[])
    service.cluster_reader=lambda *args:Reader()
    service.model_context=lambda engine:(ModelProfileConfig(provider_label='test',base_url='https://model.invalid',
        chat_model='test',embedding_model=None,timeout_seconds=30,max_output_tokens=2000),'model-secret')
    service.provider=Provider()
    with Session(client.app.state.engine) as db:
        rid=db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id==iid))
    service.investigate(client.app.state.engine,rid)
    assert all('private previous crash log' not in json.dumps(item) for item in coordinator_contexts)
    assert all('private historical log' not in json.dumps(item) for item in coordinator_contexts)
    with Session(client.app.state.engine) as db:
        run=db.get(IncidentRun,rid)
        assert run.status=='completed'
        assert sum(item['source']=='Pod log specialist' for item in json.loads(run.evidence_json))==2


def test_reader_denies_arbitrary_paths_and_projects():
    calls=[]
    def respond(request):
        calls.append(request)
        return httpx.Response(200,json={'items':[{'metadata':{'name':'app'},'spec':{'project':'userland','destination':{'server':'https://target'}},'status':{'history':[]}}]})
    reader=IncidentReader('https://host','credential',namespaces=['openshift-etcd'],
        transport=httpx.MockTransport(respond))
    with pytest.raises(ValueError): reader.collect('pods:customer')
    assert calls==[]
    result=reader.argocd(['platform'],{'https://target'},[],datetime.now(timezone.utc))
    assert result['changes']==[]
    assert all(r.method=='GET' for r in calls)
    assert calls[0].url.path=='/api/v1/applications'
    reader.close()


def test_reader_exposes_only_configured_incident_namespaces():
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'items': []})

    reader = IncidentReader('https://host', 'credential', namespaces=['team-checkout'],
        transport=httpx.MockTransport(respond))
    assert 'pods:team-checkout' in reader.catalog()
    assert reader.collect('events:team-checkout')['scope'] == 'events:team-checkout'
    with pytest.raises(ValueError):
        reader.collect('pods:openshift-etcd')
    assert len(calls) == 1
    with pytest.raises(ValueError):
        IncidentReader('https://host', 'credential', namespaces=['../customer'])
    reader.close()


def test_cluster_health_discovers_cross_namespace_workload_and_storage_scope():
    now = datetime.now(timezone.utc).isoformat()

    def respond(request):
        if request.url.path == '/api/v1/pods':
            return httpx.Response(200, json={'items': [{
                'metadata': {'name': 'image-registry-0', 'namespace': 'openshift-image-registry'},
                'spec': {'volumes': [{'name': 'storage', 'persistentVolumeClaim': {
                    'claimName': 'registry-storage',
                }}]},
                'status': {'phase': 'Pending', 'containerStatuses': [{
                    'name': 'registry', 'ready': False,
                    'state': {'waiting': {'reason': 'ContainerCreating'}},
                }]},
            }]})
        if request.url.path == '/api/v1/persistentvolumeclaims':
            return httpx.Response(200, json={'items': [{
                'metadata': {'name': 'registry-storage', 'namespace': 'openshift-image-registry'},
                'spec': {'storageClassName': 'lvms-vg1'}, 'status': {'phase': 'Pending'},
            }]})
        if request.url.path == '/api/v1/events':
            return httpx.Response(200, json={'items': [{
                'metadata': {'name': 'registry-mount', 'namespace': 'openshift-image-registry'},
                'reason': 'FailedMount', 'message': 'PVC is not available',
                'lastTimestamp': now, 'involvedObject': {'kind': 'Pod', 'name': 'image-registry-0'},
            }]})
        return httpx.Response(200, json={'items': []})

    reader = IncidentReader('https://host', 'credential',
        transport=httpx.MockTransport(respond))
    result = reader.collect('cluster-health')
    assert {row['kind'] for row in result['rows']} == {
        'Pod', 'PersistentVolumeClaim', 'Event',
    }
    assert result['discovered_namespaces'] == ['openshift-image-registry']
    pod = next(row for row in result['rows'] if row['kind'] == 'Pod')
    assert pod['persistent_volume_claims'] == ['registry-storage']
    assert 'pods:openshift-image-registry' in reader.catalog()
    assert 'events:openshift-image-registry' in reader.catalog()
    assert 'storage:openshift-image-registry' in reader.catalog()
    assert result['partial'] is False
    assert result['limitations'] == []
    reader.close()


def test_cluster_health_reports_sanitized_failures_and_actual_pagination():
    requests=[]
    def respond(request):
        requests.append(request)
        if request.url.path == '/api/v1/pods':
            return httpx.Response(403, json={'message': 'credential detail must not be retained'})
        if request.url.path == '/apis/apps/v1/deployments':
            if request.url.params.get('continue') == 'opaque-server-token':
                return httpx.Response(200, json={'items': [{
                    'metadata': {'name': 'unavailable-app', 'namespace': 'team-b'},
                    'spec': {'replicas': 2}, 'status': {'availableReplicas': 1},
                }]})
            return httpx.Response(200, json={
                'metadata': {'continue': 'opaque-server-token'},
                'items': [{'metadata': {'name': f'app-{index}', 'namespace': 'team-a'},
                    'spec': {'replicas': 1}, 'status': {'availableReplicas': 1}}
                    for index in range(60)],
            })
        return httpx.Response(200, json={'items': []})

    reader = IncidentReader('https://host', 'credential',
        transport=httpx.MockTransport(respond))
    result = reader.collect('cluster-health')

    assert result['partial'] is True
    assert result['limitations'] == [
        'Cluster-wide Pod health survey failed: Kubernetes API returned HTTP 403.',
    ]
    deployment_coverage=next(item for item in result['coverage'] if item['kind']=='Deployment')
    assert deployment_coverage == {
        'kind': 'Deployment', 'pages': 2, 'scanned': 61,
        'unhealthy': 1, 'complete': True,
    }
    assert result['rows'] == [{
        'kind': 'Deployment', 'namespace': 'team-b', 'name': 'unavailable-app',
        'desired': 2, 'ready': 1, 'generation': None, 'observed_generation': None,
    }]
    second_page=next(request for request in requests
        if request.url.path=='/apis/apps/v1/deployments'
        and request.url.params.get('continue'))
    assert second_page.url.params['continue']=='opaque-server-token'
    assert 'credential detail' not in json.dumps(result)
    reader.close()


def test_cluster_health_scans_all_pages_while_bounding_retained_exceptions():
    def respond(request):
        if request.url.path != '/api/v1/pods':
            return httpx.Response(200,json={'items':[]})
        token=request.url.params.get('continue')
        start={'':0,'page-2':60,'page-3':120}[token or '']
        count=10 if token=='page-3' else 60
        next_token={'':'page-2','page-2':'page-3','page-3':''}[token or '']
        return httpx.Response(200,json={
            'metadata':{'continue':next_token},
            'items':[{
                'metadata':{'name':f'pending-{index}','namespace':f'team-{index}'},
                'spec':{'containers':[]}, 'status':{'phase':'Pending'},
            } for index in range(start,start+count)],
        })

    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(respond))
    result=reader.collect('cluster-health')

    pod_coverage=next(item for item in result['coverage'] if item['kind']=='Pod')
    assert pod_coverage == {
        'kind':'Pod','pages':3,'scanned':130,'unhealthy':130,'complete':True,
    }
    assert len(result['rows'])==130
    assert result['rows'][0]['name']=='pending-0'
    assert result['rows'][-1]['name']=='pending-129'
    assert len(result['discovered_namespaces'])==130
    assert result['partial'] is False
    assert result['limitations']==[]
    reader.close()


def test_namespaced_collection_reports_pagination_only_when_reached():
    responses = iter((
        httpx.Response(200, json={'items': []}),
        httpx.Response(200, json={
            'metadata': {'continue': 'opaque-server-token'},
            'items': [{'metadata': {'name': f'pod-{index}', 'namespace': 'team-a'},
                'spec': {'containers': []}, 'status': {'phase': 'Running'}}
                for index in range(60)],
        }),
        httpx.Response(200, json={"items": [{"metadata": {"name": "last-pod"}}]}),
    ))
    reader = IncidentReader('https://host', 'credential', namespaces=['team-a'],
        transport=httpx.MockTransport(lambda _request: next(responses)))

    complete = reader.collect('events:team-a')
    partial = reader.collect('pods:team-a')

    assert complete['partial'] is False
    assert complete['limitations'] == []
    assert partial['partial'] is False
    assert partial['limitations'] == []
    assert len(partial['rows']) == 61
    assert partial['rows'][-1]['name'] == 'last-pod'
    reader.close()


def test_degraded_cluster_operator_exposes_related_namespace_scope():
    payload = {'items': [{
        'metadata': {'name': 'image-registry'},
        'status': {
            'conditions': [
                {'type': 'Available', 'status': 'False', 'reason': 'Unavailable'},
                {'type': 'Degraded', 'status': 'True', 'reason': 'StorageError'},
            ],
            'relatedObjects': [{
                'group': '', 'resource': 'namespaces', 'name': 'openshift-image-registry',
            }, {
                'group': '', 'resource': 'pods', 'namespace': 'openshift-image-registry',
                'name': 'image-registry-0',
            }, {
                'group': '', 'resource': 'secrets', 'namespace': 'openshift-image-registry',
                'name': 'registry-secret',
            }],
        },
    }]}
    reader = IncidentReader('https://host', 'credential',
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=payload)))
    result = reader.collect('operators')
    assert result['rows'][0]['related_objects'] == [{
        'resource': 'namespaces', 'name': 'openshift-image-registry',
    }, {
        'resource': 'pods', 'namespace': 'openshift-image-registry',
        'name': 'image-registry-0',
    }]
    assert 'pods:openshift-image-registry' in reader.catalog()
    reader.close()


def test_redaction_preserves_json_structure():
    assert clean_evidence({'password':'secret','message':'token=secret and abc'},['abc']) == {
        'password':'[REDACTED]', 'message':'token=[REDACTED] and [REDACTED]'}


def test_incident_component_preserves_proxy_args():
    from pathlib import Path
    import yaml
    root=Path(__file__).resolve().parents[3]
    base=yaml.safe_load((root/'deploy/openshift/workload/deployment.yaml').read_text())
    patch=yaml.safe_load((root/'deploy/openshift/components/incident-response/deployment-patch.yaml').read_text())
    original=next(c for c in base['spec']['template']['spec']['containers'] if c['name']=='oauth-proxy')['args']
    updated=next(c for c in patch['spec']['template']['spec']['containers'] if c['name']=='oauth-proxy')['args']
    assert updated[:-1]==original
    assert updated[-1]=='--skip-auth-regex=^/api/v1/incident-webhooks/[a-f0-9-]+$'


def test_continue_handoff_is_owned_read_only_and_requires_delegation(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    headers=admin_headers(client)
    assert client.post(f'/api/v1/incidents/{iid}/continue',headers=headers).status_code==409
    client.app.state.settings.delegated_access_enabled=True
    with Session(client.app.state.engine) as db:
        run=db.scalar(select(IncidentRun)); run.status='completed'
        incident_run_id=run.id
        run.briefing_json=json.dumps({'summary':'Preliminary hypothesis'})
        run.evidence_json=json.dumps([{'id':'E1','observed_at':'2026-09-05T12:00:00Z','source':'operators','data':{'rows':[]}}])
        db.commit()
    result=client.post(f'/api/v1/incidents/{iid}/continue',headers=headers)
    assert result.status_code==200
    cid=result.json()['url'].split('/')[-1]
    with Session(client.app.state.engine) as db:
        conversation=db.get(AdHocConversation,cid)
        assert conversation.execution_mode=='read_only'
        assert conversation.delegated_session_id
        assert conversation.created_by=='admin'
        assert 'private-cluster-token' not in conversation.evidence_json
        assert json.loads(conversation.evidence_json)[0]['origin'] == {
            'type': 'incident', 'incident_id': iid, 'run_id': incident_run_id, 'evidence_id': 'E1',
        }
        handoff=json.loads(conversation.handoff_json)
        assert handoff['status']=='pending'
        assert handoff['incident_id']==iid
        assert handoff['run_number']==1
        assert handoff['evidence_count']==1
        assert db.scalar(select(func.count()).select_from(AdHocMessage).where(
            AdHocMessage.conversation_id==cid))==0
    page=client.get(result.json()['url'],headers={'x-forwarded-user':'admin'})
    assert page.status_code==200
    assert 'Preliminary hypothesis' in page.text
    assert 'Imported incident context' in page.text
    assert 'Waiting for cluster sign-in.' in page.text
    assert 'data-incident-handoff-start-url' not in page.text
    assert 'Incident handoff:' not in page.text
    assert client.get(result.json()['url'],headers={'x-forwarded-user':'sre'}).status_code==404

    with Session(client.app.state.engine) as db:
        db.add(ModelProfile(
            id=1, provider_label='Test model', base_url='https://model.example/v1',
            chat_model='test-agent', api_type='responses', embedding_model=None,
            timeout_seconds=30, max_output_tokens=1200, status='ready',
            capabilities_json='{"tool_calls": true}', updated_by='admin',
        ))
        db.commit()
    delegated_session_id=client.app.state.delegated_vault.new_session_id()
    client.app.state.delegated_vault.put(
        session_id=delegated_session_id, owner='admin', cluster_id=SYSTEM_CLUSTER_ID,
        remote_username='admin', remote_uid='uid-admin', token='delegated-cluster-token',
    )
    client.cookies.set('podpilot_delegated_session',delegated_session_id)
    ready=client.get(result.json()['url'],headers={'x-forwarded-user':'admin'})
    assert 'data-incident-handoff-start-url=' in ready.text
    # The fixture has no background worker; leave the claimed run queued for endpoint assertions.
    client.app.state.settings.adhoc_job_worker_enabled=True
    client.app.state.adhoc_wake=SimpleNamespace(set=lambda: None)
    started=client.post(
        f'/api/v1/adhoc-conversations/{cid}/incident-handoff/start', headers=admin_headers(client),
    )
    assert started.status_code==202,started.text
    duplicate=client.post(
        f'/api/v1/adhoc-conversations/{cid}/incident-handoff/start', headers=admin_headers(client),
    )
    assert duplicate.status_code==200
    assert duplicate.json()['status']=='already_started'
    with Session(client.app.state.engine) as db:
        conversation=db.get(AdHocConversation,cid)
        messages=list(db.scalars(select(AdHocMessage).where(AdHocMessage.conversation_id==cid)))
        runs=list(db.scalars(select(AdHocRun).where(AdHocRun.conversation_id==cid)))
        assert conversation.handoff_run_id==started.json()['run_id']
        assert json.loads(conversation.handoff_json)['status']=='submitted'
        assert len(messages)==1 and messages[0].role=='user' and messages[0].actor=='admin'
        assert messages[0].content.startswith('Continue investigating incident')
        assert len(runs)==1 and runs[0].id==conversation.handoff_run_id
    client.app.state.delegated_vault.pop_session(session_id=delegated_session_id,owner='admin')


def test_logs_only_become_available_for_observed_platform_containers():
    requests=[]
    def respond(request):
        requests.append(request)
        if request.url.path.endswith('/log'):
            return httpx.Response(200,text='2026-09-05T12:00:00Z test logs')
        return httpx.Response(200,json={'items':[{'metadata':{'name':'etcd-0'},
            'spec':{'containers':[{'name':'etcd','image':'example/etcd','env':[{'name':'PASSWORD','value':'never-send'}]}]},
            'status':{'phase':'Running'}}]})
    reader=IncidentReader('https://host','credential',namespaces=['openshift-etcd'],
        transport=httpx.MockTransport(respond))
    assert not any(k.startswith('logs:') for k in reader.catalog())
    evidence=reader.collect('pods:openshift-etcd')
    assert 'never-send' not in json.dumps(evidence)
    assert not any(k.startswith('logs-previous:') for k in reader.catalog())
    key=next(k for k in reader.catalog() if k.startswith('logs:'))
    assert 'test logs' in reader.collect(key)['logs']
    assert requests[-1].url.params['tailLines']=='1000'
    assert requests[-1].url.params['limitBytes']=='98304'
    assert requests[-1].url.params['sinceSeconds']=='7200'
    reader.close()


def test_restarted_container_exposes_previous_logs_and_scoped_loki_history():
    requests=[]
    def respond(request):
        requests.append(request)
        if request.url.path.endswith('/log'):
            return httpx.Response(200,text='previous crash output')
        return httpx.Response(200,json={'items':[{'metadata':{'name':'etcd-0'},
            'spec':{'containers':[{'name':'etcd','image':'example/etcd'}]},
            'status':{'phase':'Running','containerStatuses':[{'name':'etcd','restartCount':2,
                'lastState':{'terminated':{'exitCode':1,'reason':'Error'}}}]}}]})
    reader=IncidentReader('https://host','credential',namespaces=['openshift-etcd'],
        transport=httpx.MockTransport(respond))
    reader.loki=SimpleNamespace()
    pods=reader.collect('pods:openshift-etcd')
    assert pods['rows'][0]['containers'][0]['lastState']['terminated']['exitCode']==1
    previous=next(key for key in reader.catalog() if key.startswith('logs-previous:'))
    assert any(key.startswith('loki-logs:') for key in reader.catalog())
    result=reader.collect(previous)
    assert result['previous'] is True
    assert result['logs']=='previous crash output'
    assert result['limitations'] == []
    assert requests[-1].url.params['previous']=='true'
    assert 'sinceSeconds' not in requests[-1].url.params
    reader.close()


def test_missing_previous_logs_fall_back_to_exact_loki_container_history():
    class Loki:
        calls=[]
        def query_container_logs(self, **kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(entries=(
                SimpleNamespace(timestamp_ns='2',line='newer failure'),
                SimpleNamespace(timestamp_ns='1',line='older context'),
            ), is_complete=True)
    def respond(request):
        if request.url.path.endswith('/log'):
            return httpx.Response(400,text='previous terminated container not found')
        return httpx.Response(200,json={'items':[{'metadata':{'name':'api-0'},
            'spec':{'containers':[{'name':'api'}]},
            'status':{'containerStatuses':[{'name':'api','restartCount':1}]}}]})
    reader=IncidentReader('https://host','credential',namespaces=['openshift-etcd'],
        transport=httpx.MockTransport(respond))
    reader.loki=Loki()
    reader.set_log_window(datetime.now(timezone.utc)-timedelta(hours=1))
    reader.collect('pods:openshift-etcd')
    previous=next(key for key in reader.catalog() if key.startswith('logs-previous:'))
    result=reader.collect(previous)
    assert result['mechanism']=='loki-infrastructure-query'
    assert result['logs'].splitlines()==['1 older context','2 newer failure']
    assert result['kubernetes_previous_error']=='Previous container logs request returned HTTP 400.'
    assert result['limitations'][0].startswith(
        'Previous Kubernetes logs failed: Previous container logs request returned HTTP 400.'
    )
    assert Loki.calls[0]['namespace']=='openshift-etcd'
    assert Loki.calls[0]['pod']=='api-0'
    assert Loki.calls[0]['container']=='api'
    reader.close()


def test_event_projection_keeps_ranked_rows_instead_of_discarding_collection():
    now=datetime.now(timezone.utc).isoformat()
    items=[]
    for index in range(60):
        items.append({'metadata':{'name':f'event-{index}','creationTimestamp':now},
            'reason':'FailedMount' if index==59 else 'GenericWarning',
            'message':('important failure ' if index==59 else 'routine warning ')*180,
            'type':'Warning','lastTimestamp':now,'involvedObject':{'kind':'Pod','name':f'pod-{index}'}})
    reader=IncidentReader('https://host','credential',namespaces=['openshift-monitoring'],
        transport=httpx.MockTransport(lambda _request:httpx.Response(200,json={'items':items})))
    result=reader.collect('events:openshift-monitoring')
    assert len(result['rows']) == len(items)
    assert any(row['reason']=='FailedMount' for row in result['rows'])
    assert result['partial'] is False
    assert result['limitations'] == []
    reader.close()


def test_system_projection_limit_suppresses_model_paraphrase():
    system=['events:openshift-monitoring: evidence projection retained 8 of 60 rows.']
    model=[
        'The `events:openshift-monitoring` collector exceeded its projection limit, so event coverage is incomplete.',
        'The exact alert-generation path remains unknown.',
    ]
    filtered=_dedupe_limitations(model, exclude_keys={_limitation_key(item) for item in system})
    assert filtered==['The exact alert-generation path remains unknown.']


def test_evidence_limitations_separate_collectors_from_model_specialists():
    evidence = [
        {'source': 'cluster-health', 'data': {'limitations': ['Pod survey returned HTTP 403.']}},
        {'source': 'Argo CD specialist', 'data': {'limitations': ['Deployment timing remains uncertain.']}},
    ]

    assert _evidence_limitations(evidence, model_authored=False) == [
        'cluster-health: Pod survey returned HTTP 403.'
    ]
    assert _evidence_limitations(evidence, model_authored=True) == [
        'Argo CD specialist: Deployment timing remains uncertain.'
    ]


def test_argocd_correlates_only_exact_target_project_and_window():
    def application(project, server, stamp):
        return {'metadata':{'name':'platform'}, 'spec':{'project':project,'destination':{'server':server},
            'source':{'repoURL':'https://git.example/platform/config','path':'clusters/dev-east'}},
            'status':{'sync':{'status':'Synced','revision':'a'*40},
                'resources':[{'group':'apps','kind':'Deployment','namespace':'platform','name':'operator'}],
                'history':[{'deployedAt':stamp,'source':{'repoURL':'https://git.example/platform/config',
                    'path':'clusters/dev-east'},'revision':'a'*40}]}}
    apps=[application('platform','https://target','2026-09-05T12:00:00Z'),
          application('userland','https://target','2026-09-05T12:00:00Z'),
          application('platform','https://other','2026-09-05T12:00:00Z'),
          application('platform','https://target','2026-01-01T12:00:00Z')]
    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'items':apps})))
    result=reader.argocd(['platform'],{'https://target'},[],datetime(2026,9,5,tzinfo=timezone.utc))
    assert len(result['changes'])==1
    assert len(result['applications'])==2
    assert result['changes'][0]['path']=='clusters/dev-east'
    assert result['applications'][0]['managed_resources'][0]['name']=='operator'
    assert result['applications'][0]['sources'][0]['deployed_revision']=='a'*40
    inventory=reader.argocd(['platform'],set(),set(),datetime(2010,1,1,tzinfo=timezone.utc))
    assert len(inventory['applications'])==3
    reader.close()


def test_github_reads_metadata_without_forwarding_redirects_or_diffs():
    calls=[]
    def respond(request):
        calls.append(request)
        if '/git/commits/' in request.url.path:
            return httpx.Response(200,json={'message':'Deploy platform\nprivate body','author':{'name':'SRE'}})
        return httpx.Response(200,json=[{'number':42,'title':'Platform update','body':'private body','user':{'login':'sre'},'html_url':'https://evil.invalid'}])
    reader=IncidentReader('https://git.example','pat',transport=httpx.MockTransport(respond))
    result=reader.github('platform/config','a'*40,'/api/v3')
    assert 'private body' not in json.dumps(result)
    assert result['pull_requests'][0]['url']=='https://git.example/platform/config/pull/42'
    assert all(request.headers['Authorization']=='Bearer pat' for request in calls)
    assert '/git/commits/' in calls[0].url.path
    reader.close()
    reader=IncidentReader('https://git.example','pat',transport=httpx.MockTransport(lambda r:httpx.Response(302,headers={'Location':'https://evil.invalid'})))
    with pytest.raises(ValueError): reader.github('platform/config','a'*40,'/api/v3')
    reader.close()


def test_migration_upgrade_and_downgrade(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect
    from podpilot_api.settings import get_settings
    # CLI migration logging must not disable application loggers in the surrounding suite.
    monkeypatch.setattr('logging.config.fileConfig', lambda *args, **kwargs: None)
    monkeypatch.setenv('PODPILOT_DATABASE_URL',f'sqlite:///{tmp_path / "migration.db"}')
    get_settings.cache_clear()
    try:
        config=Config('apps/api/alembic.ini')
        command.upgrade(config,'head')
        engine=create_engine(f'sqlite:///{tmp_path / "migration.db"}')
        assert {'fleet_incidents','incident_connections','incident_runs','connector_discoveries'} <= set(inspect(engine).get_table_names())
        assert {'handoff_json','handoff_run_id'} <= {
            column['name'] for column in inspect(engine).get_columns('adhoc_conversations')
        }
        engine.dispose()
        command.downgrade(config,'0022_live_run_operations')
        engine=create_engine(f'sqlite:///{tmp_path / "migration.db"}')
        assert not {'fleet_incidents','connector_discoveries'} & set(inspect(engine).get_table_names())
        engine.dispose()
        command.upgrade(config,'head')
    finally:
        get_settings.cache_clear()


def test_argocd_owns_an_independent_endpoint_and_credential(client):
    source(client)
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'DEV GitOps','enabled':True,'url':'https://argocd.example',
        'token':'independent-argocd-token','projects':['platform']})
    assert response.status_code==200,response.text
    with Session(client.app.state.engine) as db:
        row=db.get(IncidentConnection,response.json()['id'])
        assert row.cluster_id is None
        assert client.app.state.incident_service.token_for(row,db)=='independent-argocd-token'


def test_argocd_kubernetes_access_reuses_selected_cluster_credential(client):
    with Session(client.app.state.engine) as db:
        cluster=db.get(Cluster,SYSTEM_CLUSTER_ID)
        cluster.credential_key='registered-system-cluster'
        db.commit()
    client.app.state.incident_service.cluster_store.set('stored-cluster-reader','registered-system-cluster')
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'Hosted GitOps','enabled':True,'access_mode':'kubernetes',
        'cluster_id':SYSTEM_CLUSTER_ID,'namespace':'openshift-gitops','projects':['platform']})
    assert response.status_code==200,response.text
    with Session(client.app.state.engine) as db:
        row=db.get(IncidentConnection,response.json()['id'])
        config=json.loads(row.config_json)
        assert config['access_mode']=='kubernetes' and config['url']==''
        assert client.app.state.incident_service.token_for(row,db)=='stored-cluster-reader'
        assert client.app.state.incident_service.credentials().get(row.credential_key) is None
    page=client.get('/settings/connectors?edit='+response.json()['id'],headers={'x-forwarded-user':'admin'})
    assert 'Kubernetes API' in page.text and 'System' in page.text
    assert 'name="access_mode"' in page.text and 'name="cluster_id"' in page.text
    assert 'stored read-only Kubernetes credential' in page.text


def test_connector_discovery_builds_exact_application_topology(client):
    source(client)
    remote_id='11111111-1111-1111-1111-111111111111'
    with Session(client.app.state.engine) as db:
        db.add(Cluster(id=remote_id,name='Remote GitOps host',
            api_url='https://api.remote.example:6443',environment='dev',visibility='shared',
            is_enabled=True,is_system=False,status='ready',created_by='admin',updated_by='admin'))
        db.commit()
    cluster=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'cluster','name':'Remote incidents','cluster_id':remote_id,'enabled':True,
        'token':'remote-cluster-reader','webhook_token':'r'*40})
    github=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'github','name':'GitHub.com','enabled':True,'url':'https://api.github.com',
        'api_prefix':'','token':'github-token','repositories':['platform/config']})
    argocd=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'Central Argo','enabled':True,'access_mode':'kubernetes',
        'cluster_id':remote_id,'namespace':'openshift-gitops','projects':['platform']})
    assert cluster.status_code==200 and github.status_code==200 and argocd.status_code==200
    service=client.app.state.incident_service
    class Reader:
        def __init__(self,origin): self.origin=origin
        def get(self,path,*args):
            assert path=='/repos/platform/config'
            return {'full_name':'platform/config','default_branch':'main','html_url':'https://github.com/platform/config'}
        def argocd(self,*args,**kwargs):
            return {'applications':[{'application':'payments-dev','project':'platform',
                'destination':{'server':'https://kubernetes.default.svc','name':None,'namespace':'payments'},
                'sources':[{'repository':'https://github.com/platform/config.git','path':'clusters/dev',
                    'target_revision':'main','deployed_revision':'a'*40}],
                'managed_resources':[],'health':'Healthy','sync':'Synced'}],
                'changes':[],'partial':False,'limitations':[]}
        def close(self): pass
    service.reader_factory=lambda origin,*args,**kwargs:Reader(origin)
    for connection_id in (github.json()['id'],argocd.json()['id']):
        assert service.queue_discovery(client.app.state.engine,connection_id,'admin')['queued']
        service.discover_connection(client.app.state.engine,connection_id)
    page=client.get('/settings/connectors',headers={'x-forwarded-user':'admin'})
    assert 'payments-dev' in page.text and 'clusters/dev' in page.text
    assert 'GitHub.com' in page.text and 'Central Argo' in page.text
    assert 'Remote GitOps host' in page.text
    assert 'Confirmed' in page.text and 'Live discovery' not in page.text


def test_enabled_connector_save_queues_discovery(client):
    service=client.app.state.incident_service
    service.settings.incident_connector_discovery_enabled=True
    started=threading.Event()
    discovered=[]
    def discover(_engine,connection_id):
        discovered.append(connection_id)
        started.set()
    service.discover_connection=discover
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'github','name':'Queued GitHub','enabled':True,'url':'https://github.example',
        'token':'github-token','repositories':['platform/config']})
    assert response.status_code==200,response.text
    assert response.json()['discovery_status']=='queued'
    assert started.wait(1) and discovered==[response.json()['id']]


def test_worker_restart_marks_inflight_interrupted_without_rerun(client):
    import asyncio
    source_id=source(client); send(client,source_id,notification())
    with Session(client.app.state.engine) as db:
        row=db.scalar(select(IncidentRun)); row.status='running'; rid=row.id; db.commit()
    async def run_worker():
        task=asyncio.create_task(client.app.state.incident_service.worker(client.app))
        await asyncio.sleep(.05)
        task.cancel()
        await asyncio.gather(task,return_exceptions=True)
    asyncio.run(run_worker())
    with Session(client.app.state.engine) as db:
        assert db.get(IncidentRun,rid).status=='interrupted'
        assert db.scalar(select(func.count()).select_from(IncidentRun))==1


def test_incident_worker_runs_three_queued_incidents_concurrently(client):
    import asyncio
    sid=source(client)
    for index in range(3):
        body=notification(starts=f'2026-09-05T1{index}:00:00Z')
        body['groupKey']=f'parallel/{index}'
        body['alerts'][0]['fingerprint']=f'parallel-{index}'
        send(client,sid,body)
    service=client.app.state.incident_service
    barrier=threading.Barrier(3); threads=set(); commit_lock=threading.Lock()
    def investigate(engine,run_id):
        threads.add(threading.get_ident())
        barrier.wait(timeout=2)
        with commit_lock, Session(engine) as db:
            db.execute(update(IncidentRun).where(IncidentRun.id==run_id).values(status='completed'))
            db.commit()
    service.investigate=investigate
    async def run_worker():
        task=asyncio.create_task(service.worker(client.app))
        for _ in range(100):
            await asyncio.sleep(.02)
            with Session(client.app.state.engine) as db:
                if db.scalar(select(func.count()).select_from(IncidentRun).where(IncidentRun.status=='completed'))==3:
                    break
        task.cancel()
        await asyncio.gather(task,return_exceptions=True)
    asyncio.run(run_worker())
    assert len(threads)==3


def test_webhook_rejects_naive_dates_and_oversized_payload(client):
    sid=source(client)
    body=notification(starts='2026-09-05T12:00:00')
    assert send(client,sid,body).status_code==422
    body=notification(); body['alerts'][0]['annotations']['summary']='x'*131072
    assert send(client,sid,body).status_code==413


def test_webhook_settings_redirects_to_cluster_connector_without_exposing_secrets(client):
    sid=source(client)
    redirect=client.get('/settings/webhooks',headers={'x-forwarded-user':'admin'},follow_redirects=False)
    assert redirect.status_code==303
    assert redirect.headers['location']=='/settings/connectors'
    page=client.get(f'/settings/connectors?edit={sid}',headers={'x-forwarded-user':'admin'})
    assert page.status_code==200
    assert f'/api/v1/incident-webhooks/{sid}' in page.text
    assert f'href="/settings/connectors?edit={sid}"' in page.text
    assert 'aria-current="page"' in page.text
    assert 'None yet · 0 incidents recorded' in page.text
    assert 'Configure Incident limits in Model settings' in page.text
    assert 'private-cluster-token' not in page.text and 'w'*40 not in page.text
    assert client.get('/settings/webhooks',headers={'x-forwarded-user':'sre'}).status_code==403


def test_incident_navigation_persists_sessions_and_caps_recent_incidents(client):
    sid = source(client)
    with Session(client.app.state.engine) as db:
        db.add(AdHocConversation(
            id='00000000-0000-0000-0000-000000000001', created_by='admin',
            title='Active platform investigation', status='active', evidence_json='[]'))
        for index in range(11):
            db.add(FleetIncident(
                id=f'00000000-0000-0000-0000-{index:012d}',
                cluster_id=SYSTEM_CLUSTER_ID, source_id=sid, group_key=f'group-{index}',
                title=f'Incident {index:02d}', alert_state='firing', alerts_json='{}',
                updated_at=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=index)))
        db.commit()

    connectors = client.get('/settings/connectors', headers={'x-forwarded-user':'admin'})

    assert connectors.status_code == 200
    assert 'Active platform investigation' in connectors.text
    assert 'aria-label="Recent incidents"' in connectors.text
    assert 'Incident 10' in connectors.text and 'Incident 06' in connectors.text
    assert 'Incident 05' not in connectors.text
    assert 'More incidents →' in connectors.text
    assert 'aria-label="Connector instances"' in connectors.text
    assert all(f'id="nav-connector-group-{kind}"' in connectors.text for kind in ('cluster','github','argocd'))
    assert 'SNO incidents' in connectors.text
    assert 'Webhook receivers' not in connectors.text
    assert 'Cluster registry' not in connectors.text
    assert 'class="nav-label section-gap admin-section-label">Manage</p>' in connectors.text

    assert 'href="/incidents/00000000-0000-0000-0000-000000000010"' in connectors.text
    assert len(set(re.findall(r'href="/incidents/([0-9a-f-]{36})"', connectors.text))) == 5

    base_template = (Path(__file__).parents[2] / 'web/templates/base.html').read_text(encoding='utf-8')
    assert base_template.index('href="/delegated/connect"') < base_template.index('href="/incidents"')
    assert base_template.index('href="/incidents"') < base_template.index('>Manage</p>')

    investigator = client.get('/incidents', headers={'x-forwarded-user':'sre'})
    assert investigator.status_code == 200
    assert '>Connectors</a>' not in investigator.text
    assert 'aria-label="Connectors"' not in investigator.text



def test_synthetic_incidents_are_clearly_labelled(client):
    sid=source(client)
    payload=notification(); payload['alerts'][0]['labels']['podpilot_test']='true'
    response=send(client,sid,payload)
    with Session(client.app.state.engine) as db:
        row=db.get(FleetIncident,response.json()['incident_id'])
        assert row.title=='[TEST] etcdNoLeader'

    payload=notification(starts='2026-09-05T13:00:00Z')
    payload['groupKey']='cluster/simulation'
    payload['alerts'][0]['fingerprint']='simulation-abc'
    payload['alerts'][0]['labels']['podpilot_simulation']='true'
    response=send(client,sid,payload)
    with Session(client.app.state.engine) as db:
        row=db.get(FleetIncident,response.json()['incident_id'])
        assert row.title=='[SIMULATION] etcdNoLeader'


def test_platform_projection_preserves_failures_without_large_status_bodies():
    payload={'items':[{'metadata':{'name':'etcd'},'status':{'conditions':[
        {'type':'Available','status':'True','message':'healthy '*1000},
        {'type':'Degraded','status':'True','reason':'MemberFailure','message':'failure '*1000}]}}]}
    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(lambda r:httpx.Response(200,json=payload)))
    result=reader.collect('operators')
    conditions=result['rows'][0]['conditions']
    assert conditions[0]=={'type':'Available','status':'True'}
    assert conditions[1]['reason']=='MemberFailure'
    assert len(conditions[1]['message'])==8000
    assert len(json.dumps(result)) < reader.policy.max_collection_bytes
    reader.close()
