import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from podpilot_api.auth import Role, StaticRoleResolver
from podpilot_api.database import build_engine
from podpilot_api.main import create_app, SYSTEM_CLUSTER_ID
from podpilot_api.models import Base
from podpilot_api.incident_models import IncidentConnection, FleetIncident, IncidentRun
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
    assert 'None yet' in page.text
    assert 'private-cluster-token' not in page.text and 'w'*40 not in page.text
    send(client,sid,notification())
    page=client.get('/settings/webhooks',headers={'x-forwarded-user':'admin'})
    assert '1 incidents recorded' in page.text
    assert 'None yet' not in page.text
    assert client.get('/settings/webhooks',headers={'x-forwarded-user':'sre'}).status_code==403


def test_synthetic_incidents_are_clearly_labelled(client):
    sid=source(client)
    payload=notification(); payload['alerts'][0]['labels']['podpilot_test']='true'
    response=send(client,sid,payload)
    with Session(client.app.state.engine) as db:
        row=db.get(FleetIncident,response.json()['incident_id'])
        assert row.title=='[TEST] etcdNoLeader'


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
