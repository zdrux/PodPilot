import json
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func, update
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app, SYSTEM_CLUSTER_ID
from podpilot_api.models import AdHocConversation, Base
from podpilot_api.incident_models import IncidentConnection, FleetIncident, IncidentRun
from podpilot_api.model_provider import AdHocLogAnalysis, ModelProfileConfig
from podpilot_api.settings import Settings
from podpilot_diagnostics.incidents import IncidentDecision
from podpilot_openshift.incidents import IncidentReader, clean_evidence


class Store:
    def __init__(self): self.values = {}
    def get(self, key=None): return self.values.get(key)
    def set(self, value, key=None): self.values[key] = value
    def delete(self, key=None): self.values.pop(key, None)


@pytest.fixture
def client(tmp_path):
    settings = Settings(auth_mode="test", data_dir=tmp_path,
        database_url=f"sqlite:///{tmp_path / 'incidents.db'}", incidents_enabled=True,
        incident_worker_enabled=False, adhoc_job_worker_enabled=False)
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    engine.dispose()
    app = create_app(settings=settings, role_resolver=StaticRoleResolver({
        "sre": Role.INVESTIGATOR, "admin": Role.APPROVER, "viewer": Role.VIEWER,
        "delegated": Role.DELEGATED_OPERATOR}), incident_credential_store=Store())
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
            'summary': 'The **API server is healthy** based on Evidence E1.',
            'hypotheses': [
                '1. **Synthetic signal** - verify the simulation label.\n\n'
                '| Evidence | Observation |\n|---|---|\n'
                '| E1 | `restartCount=9` |',
            ],
            'evidence_ids': ['E1'],
            'next_steps': ['- Confirm the alert rule source.'],
            'limitations': ['Only a bounded snapshot was collected.'],
        })
        run.evidence_json = json.dumps([{
            'id': 'E1', 'source': 'operators', 'observed_at': '2026-09-05T12:01:00Z',
            'data': {'rows': [{'name': 'kube-apiserver', 'available': True}]},
        }])
        run_id = run.id
        db.commit()

    page = client.get(f'/incidents/{iid}', headers={'x-forwarded-user':'sre'})

    assert page.status_code == 200
    assert 'role="tablist"' in page.text
    assert 'data-incident-tab="incident-panel-overview"' in page.text
    assert '<h2>Platform incident assessment</h2>' in page.text
    assert '<strong>API server is healthy</strong>' in page.text
    assert '**API server is healthy**' not in page.text
    assert '<td>3</td>' in page.text
    alert_table = re.search(r'<table class="incident-detail-table">(.*?)</table>', page.text, re.DOTALL).group(1)
    assert alert_table.count('<strong>etcdNoLeader</strong>') == 1
    assert '<details class="incident-alert-annotation"><summary>View alert annotation</summary>' in alert_table
    assert 'data-evidence-link' in page.text
    assert f'href="#evidence-{run_id}-E1"' in page.text
    assert f'id="evidence-{run_id}-E1"' in page.text
    assert 'class="panel incident-panel"' not in page.text
    assert '>- Confirm' not in page.text
    ranked_hypotheses = re.search(
        r'<ol class="incident-ranked-list">(.*?)</ol>', page.text, re.DOTALL,
    ).group(1)
    assert '<table>' not in ranked_hypotheses
    assert '<code>restartCount=9</code>' in ranked_hypotheses

    script = (Path(__file__).parents[2] / 'web/static/incidents.js').read_text(encoding='utf-8')
    assert "target.open = true" in script
    assert "target.scrollIntoView" in script


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
        historical_run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == historical_id))
        historical_run.status = 'completed'
        historical_run.completed_at = datetime(2026, 9, 5, 13, 3, tzinfo=timezone.utc)
        db.commit()

    page = client.get('/incidents', headers={'x-forwarded-user': 'sre'})

    assert page.status_code == 200
    assert 'data-active-incidents="1"' in page.text
    assert page.text.index('Active investigations') < page.text.index('All other investigations')
    dashboard = page.text[page.text.index('data-incident-dashboard'):]
    assert dashboard.index(active_id) < dashboard.index(historical_id)
    assert 'Waiting for platform log specialists' in page.text
    assert '1 active' in page.text and '1 queued · 1 done · 2 error' in page.text
    for state in ('running', 'queued', 'completed', 'error', 'stopped'):
        assert f'incident-activity-mark-{state}' in page.text
    assert 'Analyzing kube-apiserver logs' in page.text
    assert 'Requested bounded platform log analysis.' in page.text
    assert 'incident-activity-mark-started' in page.text
    assert 'Recent transitions' in page.text
    assert 'No related platform PR was found.' in page.text
    assert 'The PodPilot incident worker restarted before this task finished.' in page.text
    assert 'Stopped when the incident worker restarted.' not in page.text
    assert '&lt;script&gt;unsafe&lt;/script&gt;' in page.text
    assert '<script>unsafe</script>' not in page.text
    assert 'incident-live-board-4' in page.text


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


def test_incident_log_specialist_keeps_raw_logs_out_of_coordinator_context(client):
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    service=client.app.state.incident_service
    contexts=[]
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
            contexts.append(context)
            coordinator_calls=[item for item in contexts if 'specialist' not in item]
            if len(coordinator_calls)==1: return IncidentDecision(collect=['pods:openshift-etcd'])
            if len(coordinator_calls)==2: return IncidentDecision(collect=['logs:exact'])
            return IncidentDecision(summary='Log specialist found no incident anomaly.',evidence_ids=['E5'])
        def analyze_logs(self,_profile,_key,context):
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
        assert 'Analyze bounded platform logs' in specialist['work']
        assert specialist['result']=='No meaningful anomaly identified.'


def test_connector_specialist_isolated_from_coordinator_context(client):
    sid=source(client)
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'Platform GitOps','enabled':True,'cluster_id':SYSTEM_CLUSTER_ID,
        'projects':['platform'],'target_cluster_ids':[SYSTEM_CLUSTER_ID]})
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


def test_reader_denies_arbitrary_paths_and_projects():
    calls=[]
    def respond(request):
        calls.append(request)
        return httpx.Response(200,json={'items':[{'metadata':{'name':'app'},'spec':{'project':'userland','destination':{'server':'https://target'}},'status':{'history':[]}}]})
    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(respond))
    with pytest.raises(ValueError): reader.collect('pods:customer')
    assert calls==[]
    result=reader.argocd('openshift-gitops',['platform'],{'https://target'},[],datetime.now(timezone.utc))
    assert result['changes']==[]
    assert all(r.method=='GET' for r in calls)
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
    from podpilot_api.models import AdHocConversation
    sid=source(client); iid=send(client,sid,notification()).json()['incident_id']
    headers=admin_headers(client)
    assert client.post(f'/api/v1/incidents/{iid}/continue',headers=headers).status_code==409
    client.app.state.settings.delegated_access_enabled=True
    with Session(client.app.state.engine) as db:
        run=db.scalar(select(IncidentRun)); run.status='completed'
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
    page=client.get(result.json()['url'],headers={'x-forwarded-user':'admin'})
    assert page.status_code==200
    assert 'Preliminary hypothesis' in page.text
    assert client.get(result.json()['url'],headers={'x-forwarded-user':'sre'}).status_code==404


def test_logs_only_become_available_for_observed_platform_containers():
    requests=[]
    def respond(request):
        requests.append(request)
        if request.url.path.endswith('/log'):
            return httpx.Response(200,text='2026-09-05T12:00:00Z test logs')
        return httpx.Response(200,json={'items':[{'metadata':{'name':'etcd-0'},
            'spec':{'containers':[{'name':'etcd','image':'example/etcd','env':[{'name':'PASSWORD','value':'never-send'}]}]},
            'status':{'phase':'Running'}}]})
    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(respond))
    assert not any(k.startswith('logs:') for k in reader.catalog())
    evidence=reader.collect('pods:openshift-etcd')
    assert 'never-send' not in json.dumps(evidence)
    key=next(k for k in reader.catalog() if k.startswith('logs:'))
    assert 'test logs' in reader.collect(key)['logs']
    assert requests[-1].url.params['limitBytes']=='16384'
    reader.close()


def test_argocd_correlates_only_exact_target_project_and_window():
    def application(project, server, stamp):
        return {'metadata':{'name':'platform'}, 'spec':{'project':project,'destination':{'server':server}},
            'status':{'history':[{'deployedAt':stamp,'source':{'repoURL':'https://git.example/platform/config'},'revision':'a'*40}]}}
    apps=[application('platform','https://target','2026-09-05T12:00:00Z'),
          application('userland','https://target','2026-09-05T12:00:00Z'),
          application('platform','https://other','2026-09-05T12:00:00Z'),
          application('platform','https://target','2026-01-01T12:00:00Z')]
    reader=IncidentReader('https://host','credential',transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'items':apps})))
    result=reader.argocd('openshift-gitops',['platform'],{'https://target'},[],datetime(2026,9,5,tzinfo=timezone.utc))
    assert len(result['changes'])==1
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
        assert {'fleet_incidents','incident_connections','incident_runs'} <= set(inspect(engine).get_table_names())
        engine.dispose()
        command.downgrade(config,'0022_live_run_operations')
        engine=create_engine(f'sqlite:///{tmp_path / "migration.db"}')
        assert 'fleet_incidents' not in inspect(engine).get_table_names()
        engine.dispose()
        command.upgrade(config,'head')
    finally:
        get_settings.cache_clear()


def test_argocd_inherits_host_incident_credential(client):
    source(client)
    response=client.post('/api/v1/incident-connections',headers=admin_headers(client),json={
        'kind':'argocd','name':'DEV GitOps','enabled':True,'cluster_id':SYSTEM_CLUSTER_ID,
        'projects':['platform'],'target_cluster_ids':[SYSTEM_CLUSTER_ID]})
    assert response.status_code==200,response.text
    with Session(client.app.state.engine) as db:
        row=db.get(IncidentConnection,response.json()['id'])
        assert client.app.state.incident_service.token_for(row,db)=='private-cluster-token'


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


def test_webhook_settings_shows_receiver_and_delivery_without_secrets(client):
    sid=source(client)
    page=client.get('/settings/webhooks',headers={'x-forwarded-user':'admin'})
    assert page.status_code==200
    assert f'/api/v1/incident-webhooks/{sid}' in page.text
    assert '64000 tokens' in page.text
    assert 'None yet' in page.text
    assert 'private-cluster-token' not in page.text and 'w'*40 not in page.text
    send(client,sid,notification())
    page=client.get('/settings/webhooks',headers={'x-forwarded-user':'admin'})
    assert '1 incidents recorded' in page.text
    assert 'None yet' not in page.text
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
    webhooks = client.get('/settings/webhooks', headers={'x-forwarded-user':'admin'})

    for page in (connectors, webhooks):
        assert page.status_code == 200
        assert 'Active platform investigation' in page.text
        assert 'aria-label="Recent incidents"' in page.text
        assert 'Incident 10' in page.text and 'Incident 06' in page.text
        assert 'Incident 05' not in page.text
        assert 'More incidents →' in page.text
        assert 'aria-label="Connections and webhooks"' in page.text
        assert 'Investigation access &amp; connectors' in page.text
        assert 'Webhook receivers' in page.text
        assert 'Cluster registry' not in page.text
        assert 'class="nav-label section-gap admin-section-label">Manage</p>' in page.text

    assert 'href="/incidents/00000000-0000-0000-0000-000000000010"' in connectors.text
    assert len(set(re.findall(r'href="/incidents/([0-9a-f-]{36})"', connectors.text))) == 5

    base_template = (Path(__file__).parents[2] / 'web/templates/base.html').read_text(encoding='utf-8')
    assert base_template.index('href="/delegated/connect"') < base_template.index('href="/incidents"')
    assert base_template.index('href="/incidents"') < base_template.index('>Manage</p>')

    investigator = client.get('/incidents', headers={'x-forwarded-user':'sre'})
    assert investigator.status_code == 200
    assert 'Connections &amp; webhooks' not in investigator.text
    assert 'aria-label="Connections and webhooks"' not in investigator.text



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
    assert len(conditions[1]['message'])==200
    assert len(json.dumps(result))<1000
    reader.close()
