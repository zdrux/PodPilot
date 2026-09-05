"""Configure/test the disposable SNO webhook after dot-sourcing connect-sno.ps1.

Secrets stay in Kubernetes or an external local backup. Never emit secret material.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import yaml
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from podpilot_diagnostics.incidents import DEFAULT_ALERTS
from podpilot_openshift.delegated import tls_context

NAMESPACE = 'ai-ops'
MONITORING = 'openshift-monitoring'
TEST_RULE = 'podpilot-webhook-smoke-test'
RECEIVER = 'podpilot-platform-incidents'
CA_SECRET = 'podpilot-webhook-ca'


def oc(*args, stdin=None):
    result = subprocess.run(['oc', *args], input=stdin, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f'oc operation failed: {args[0]} (output suppressed to protect credentials)')
    return result.stdout


def backup(name, data):
    root = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'PodPilot' / 'incident-backups'
    root.mkdir(parents=True, exist_ok=True)
    path = root / f'{name}-{datetime.now(timezone.utc):%Y%m%d%H%M%S}.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    return path


def upsert_secret(core, name, namespace, data):
    try:
        current = core.read_namespaced_secret(name, namespace)
        core.patch_namespaced_secret(name, namespace, {'metadata':{'resourceVersion':current.metadata.resource_version},'data':data})
    except ApiException as exc:
        if exc.status != 404:
            raise
        core.create_namespaced_secret(namespace, client.V1Secret(metadata=client.V1ObjectMeta(name=name), data=data))


def configure(core, custom):
    ca = base64.b64decode(core.read_namespaced_secret('router-ca','openshift-ingress-operator').data['tls.crt']).decode()
    host = custom.get_namespaced_custom_object('route.openshift.io','v1',NAMESPACE,'routes','podpilot')['spec']['host']
    reader_token = oc('create','token','podpilot-incident-reader','-n',NAMESPACE,'--duration=24h').strip()
    webhook_token = secrets.token_urlsafe(40)
    # Use the same server-owned service as the configuration API, including validation and audit.
    configure_code = '''
import json,sys
from sqlalchemy import select
from sqlalchemy.orm import Session
from podpilot_api.settings import get_settings
from podpilot_api.database import build_engine
from podpilot_api.auth import AuthContext,Role
from podpilot_api.incidents import IncidentService,ConnectionInput
from podpilot_api.incident_models import IncidentConnection
settings=get_settings(); engine=build_engine(settings); data=json.load(sys.stdin)
service=IncidentService(settings,None,None,None)
with Session(engine) as db:
    existing=db.scalar(select(IncidentConnection).where(IncidentConnection.kind=='cluster',IncidentConnection.cluster_id=='00000000-0000-0000-0000-000000000001'))
    if existing:
        data['id']=existing.id
        data['webhook_token']=service.credentials().get(existing.webhook_key) or data['webhook_token']
data['custom_ca_pem']=settings.service_ca_path.read_text()
result=service.save(engine,ConnectionInput(**data),AuthContext('system:sno-incident-setup',Role.APPROVER,True))
print(json.dumps(result))
'''
    saved = json.loads(oc('exec','-i','deployment/podpilot','-n',NAMESPACE,'-c','api','--','python','-c',configure_code,
        stdin=json.dumps({'kind':'cluster','name':'SNO platform investigations','cluster_id':'00000000-0000-0000-0000-000000000001',
            'enabled':True,'token':reader_token,'webhook_token':webhook_token,
            'monitoring_url':'https://thanos-querier.openshift-monitoring.svc:9091'})))
    stored=core.read_namespaced_secret('podpilot-incident-credentials',NAMESPACE)
    webhook_token=base64.b64decode(stored.data[f'webhook-{saved["id"]}']).decode()
    endpoint = f'https://{host}/api/v1/incident-webhooks/{saved["id"]}'
    with httpx.Client(verify=tls_context(ca), timeout=20, follow_redirects=False) as http:
        unauthorized = http.post(endpoint, json={})
        if unauthorized.status_code != 401:
            raise RuntimeError(f'Webhook front door did not reject missing credentials: HTTP {unauthorized.status_code}')
        ignored = http.post(endpoint, headers={'Authorization':f'Bearer {webhook_token}'}, json={
            'groupKey':'podpilot-setup-check','status':'firing','alerts':[{
                'status':'firing','labels':{'alertname':'PodPilotNonAdmittedSetupProbe','severity':'info'},
                'startsAt':datetime.now(timezone.utc).isoformat(),'fingerprint':'setup-probe'}]})
        if ignored.status_code != 202 or ignored.json().get('accepted') != 0:
            raise RuntimeError(f'Authenticated non-admitted probe failed: HTTP {ignored.status_code}')
    print('Webhook HTTPS/authentication/parser checks passed.', flush=True)
    upsert_secret(core, CA_SECRET, MONITORING, {'ca.crt':base64.b64encode(ca.encode()).decode()})
    try:
        cm=core.read_namespaced_config_map('cluster-monitoring-config',MONITORING)
        backup('cluster-monitoring-config', {'data':cm.data})
        monitoring_config=yaml.safe_load((cm.data or {}).get('config.yaml','')) or {}
        exists=True
    except ApiException as exc:
        if exc.status != 404: raise
        monitoring_config={}; exists=False
    mounts=monitoring_config.setdefault('alertmanagerMain',{}).setdefault('secrets',[])
    if CA_SECRET not in mounts: mounts.append(CA_SECRET)
    cm_body={'data':{'config.yaml':yaml.safe_dump(monitoring_config)}}
    if exists:
        cm_body['metadata']={'resourceVersion':cm.metadata.resource_version}
        core.patch_namespaced_config_map('cluster-monitoring-config',MONITORING,cm_body)
    else:
        core.create_namespaced_config_map(MONITORING,client.V1ConfigMap(metadata=client.V1ObjectMeta(name='cluster-monitoring-config'),data=cm_body['data']))
    config_secret=core.read_namespaced_secret('alertmanager-main',MONITORING)
    backup_path=backup('alertmanager-main',{'data':config_secret.data})
    current=yaml.safe_load(base64.b64decode(config_secret.data['alertmanager.yaml']))
    existing_receivers=current.setdefault('receivers',[])
    # Repeated setup replaces our receiver and routing wrapper; it never duplicates it.
    existing_receivers[:]=[r for r in existing_receivers if r['name'] != RECEIVER]
    existing_receivers.append({'name':RECEIVER,'webhook_configs':[{'url':endpoint,'send_resolved':True,'max_alerts':100,
        'http_config':{'authorization':{'type':'Bearer','credentials':webhook_token},'follow_redirects':False,
                       'tls_config':{'ca_file':f'/etc/alertmanager/secrets/{CA_SECRET}/ca.crt'}}}]})
    old_root=current['route']
    if old_root.get('routes') and old_root['routes'][0].get('receiver') == RECEIVER:
        old_root=old_root['routes'][-1]
    wrapper=copy.deepcopy(old_root)
    wrapper['routes']=[
        {'receiver':RECEIVER,'matchers':['podpilot_test="true"'],'group_by':['alertname','podpilot_smoke_id'],
         'group_wait':'5s','group_interval':'15s','repeat_interval':'1m','continue':False},
        {'receiver':RECEIVER,'matchers':['severity="critical"','alertname=~"'+'|'.join(DEFAULT_ALERTS)+'"'],
         'group_by':['alertname'],'group_wait':'15s','group_interval':'1m','repeat_interval':'4h','continue':True},
        old_root]
    current['route']=wrapper
    rendered=yaml.safe_dump(current,sort_keys=False)
    # amtool validates syntax without printing the credential-bearing config or its diagnostics.
    check=subprocess.run(['oc','exec','-i','alertmanager-main-0','-n',MONITORING,'-c','alertmanager','--',
        '/bin/amtool','check-config','/dev/stdin'], input=rendered,text=True,capture_output=True,timeout=30)
    if check.returncode:
        raise RuntimeError('Alertmanager validation failed; original routing remains in place. Diagnostics suppressed.')
    core.patch_namespaced_secret('alertmanager-main',MONITORING,{
        'metadata':{'resourceVersion':config_secret.metadata.resource_version},
        'data':{'alertmanager.yaml':base64.b64encode(rendered.encode()).decode()}})
    expiry = json.loads(base64.urlsafe_b64decode(reader_token.split('.')[1] + '=='))['exp']
    print(json.dumps({'connection_id':saved['id'],'webhook_url':endpoint,
        'reader_token_expires_at':datetime.fromtimestamp(expiry,timezone.utc).isoformat(),
        'alertmanager_backup':str(backup_path),'receiver':RECEIVER}),flush=True)


def smoke(custom, firing):
    labels={'severity':'critical','podpilot_test':'true','podpilot_smoke_id':str(uuid4())}
    try:
        rule=custom.get_namespaced_custom_object('monitoring.coreos.com','v1',MONITORING,'prometheusrules',TEST_RULE)
        if rule['metadata'].get('labels',{}).get('app.kubernetes.io/part-of') != 'podpilot':
            raise RuntimeError('Refusing to overwrite an unowned smoke-test rule.')
        if not firing:
            labels=rule['spec']['groups'][0]['rules'][0]['labels']
    except ApiException as exc:
        if exc.status != 404: raise
        if not firing: return
    body={'apiVersion':'monitoring.coreos.com/v1','kind':'PrometheusRule',
        'metadata':{'name':TEST_RULE,'namespace':MONITORING,'labels':{'prometheus':'k8s','role':'alert-rules','app.kubernetes.io/part-of':'podpilot'}},
        'spec':{'groups':[{'name':'podpilot-webhook-smoke','interval':'15s','rules':[{
            'alert':'etcdNoLeader','expr':'vector(1)' if firing else 'vector(0) == 1','for':'15s','labels':labels,
            'annotations':{'summary':'PodPilot webhook smoke test — synthetic signal; no etcd outage is implied.',
                           'description':'Validate Alertmanager delivery and a read-only incident investigation. This is not a real platform failure.'}}]}]}}
    try:
        custom.patch_namespaced_custom_object('monitoring.coreos.com','v1',MONITORING,'prometheusrules',TEST_RULE,body)
    except ApiException as exc:
        if exc.status != 404: raise
        custom.create_namespaced_custom_object('monitoring.coreos.com','v1',MONITORING,'prometheusrules',body)
    print(json.dumps({'synthetic_rule':TEST_RULE,'firing':firing,'test_id':labels['podpilot_smoke_id']}))


def status():
    code='''
import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from podpilot_api.database import build_engine
from podpilot_api.settings import get_settings
from podpilot_api.incident_models import FleetIncident,IncidentRun
with Session(build_engine(get_settings())) as db:
    rows=[]
    for incident in db.scalars(select(FleetIncident).where(FleetIncident.title.like('[TEST]%')).order_by(FleetIncident.created_at.desc()).limit(3)):
        runs=list(db.scalars(select(IncidentRun).where(IncidentRun.incident_id==incident.id)))
        rows.append({'id':incident.id,'title':incident.title,'alert_state':incident.alert_state,'last_delivery':str(incident.updated_at),
            'runs':[{'status':r.status,'evidence_count':len(json.loads(r.evidence_json)),
                     'summary':json.loads(r.briefing_json).get('summary',''),'limitations':json.loads(r.briefing_json).get('limitations',[])} for r in runs]})
    print(json.dumps(rows))
'''
    print(oc('exec','deployment/podpilot','-n',NAMESPACE,'-c','api','--','python','-c',code))


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['configure','fire','resolve','status'])
    args=parser.parse_args()
    config.load_kube_config()
    if client.Configuration.get_default_copy().host.rstrip('/') != 'https://api.sno.192-168-0-200.sslip.io:6443':
        raise SystemExit('Refusing a cluster other than the documented disposable SNO.')
    if oc('whoami').strip() != 'system:serviceaccount:ai-ops:ai-observer':
        raise SystemExit('Connect with the short-lived ai-observer helper first.')
    try:
        if args.mode == 'configure': configure(client.CoreV1Api(),client.CustomObjectsApi())
        elif args.mode in ('fire','resolve'): smoke(client.CustomObjectsApi(),args.mode=='fire')
        else: status()
    except Exception as exc:
        # Cluster/provider exceptions may contain sensitive response bodies.
        print(f'Lab operation failed ({type(exc).__name__}); credentials and response bodies suppressed.')
        if isinstance(exc, RuntimeError): print(str(exc))
        raise SystemExit(1)
