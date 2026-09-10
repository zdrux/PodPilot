"""Read-only, secret-free findings from delegated OpenShift Alertmanager config."""
import base64
import hmac
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import yaml


def validate_alertmanager_configuration(proxy_url, *, source_id, expected_token, public_host, transport=None):
    deadline = time.monotonic() + 20
    reads = 0
    checks = []
    with httpx.Client(base_url=proxy_url.rstrip('/')+'/', timeout=5, trust_env=False,
                      follow_redirects=False, transport=transport) as http:
        def secret(namespace, name):
            nonlocal reads
            reads += 1
            if reads > 10 or time.monotonic() >= deadline:
                raise ValueError('read_budget')
            path = f'api/v1/namespaces/{namespace}/secrets/{name}'
            with http.stream('GET', path, timeout=min(5, deadline-time.monotonic())) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body)+len(chunk) > 1_000_000 or time.monotonic() >= deadline:
                        raise ValueError('read_budget')
                    body.extend(chunk)
            return json.loads(body).get('data', {})

        for namespace, name in [('openshift-monitoring', 'alertmanager-main'),
                                ('openshift-user-workload-monitoring', 'alertmanager-user-workload')]:
            finding = {'configuration': f'{namespace}/{name}', 'checks': []}
            checks.append(finding)
            try:
                data = secret(namespace, name)
                config = yaml.safe_load(base64.b64decode(data['alertmanager.yaml'], validate=True))
                if not isinstance(config, dict):
                    raise ValueError('invalid_config')
                findings = finding['checks']
                matching = []
                for receiver in config.get('receivers') or []:
                    for webhook in receiver.get('webhook_configs') or []:
                        url = urlsplit(webhook.get('url') or '')
                        if url.path != f'/api/v1/incident-webhooks/{source_id}':
                            continue
                        receiver_name = str(receiver.get('name') or '')
                        matching.append(receiver_name)
                        flags = {
                            'receiver': receiver_name[:253],
                            'https': url.scheme == 'https',
                            'host_matches_podpilot': bool(public_host and url.hostname == public_host),
                            'send_resolved': webhook.get('send_resolved', True) is True,
                            'tls_verification': not (webhook.get('http_config', {}).get('tls_config') or {}).get('insecure_skip_verify', False),
                        }
                        auth = webhook.get('http_config', {}).get('authorization') or {}
                        token = auth.get('credentials')
                        token_source = 'inline YAML'
                        if auth.get('credentials_file'):
                            token = None
                            token_source = 'file reference (unverified)'
                            # Only conventional OpenShift Secret mounts; never read arbitrary files.
                            match = re.fullmatch(r'/etc/alertmanager/secrets/([a-z0-9][a-z0-9.-]{0,252})/([A-Za-z0-9_.-]{1,253})', auth['credentials_file'])
                            if match and match[2] not in {'.', '..'}:
                                try:
                                    token = base64.b64decode(secret(namespace, match[1])[match[2]], validate=True).decode().strip()
                                    token_source = 'referenced Secret (mount not verified)'
                                except Exception:
                                    token_source = 'referenced Secret unavailable'
                        flags['token_source'] = token_source
                        flags['token_matches'] = (
                            hmac.compare_digest(token.encode(), expected_token.encode())
                            if isinstance(token, str) and expected_token else None
                        )
                        flags['bearer_auth'] = auth.get('type', 'Bearer') == 'Bearer'
                        findings.append(flags)
                # Presence of a route is a static check, not a routing simulation.
                referenced = set()
                stack = [config.get('route') or {}]
                visited = 0
                while stack:
                    route = stack.pop()
                    visited += 1
                    if visited > 1000:
                        raise ValueError('route_budget')
                    referenced.add(str(route.get('receiver') or ''))
                    stack.extend(route.get('routes') or [])
                for flags in findings:
                    flags['referenced_by_route'] = flags['receiver'] in referenced
                finding['status'] = 'review_required' if not matching or any(
                    flag.get(key) is not True for flag in findings for key in
                    ('https', 'host_matches_podpilot', 'send_resolved', 'tls_verification', 'token_matches', 'bearer_auth', 'referenced_by_route')
                ) else 'static_checks_passed'
                if not matching:
                    finding['detail'] = 'No inline webhook URL references this connector. URL-file references require manual review.'
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                finding.update(status='not_found' if code == 404 else 'denied' if code in {401, 403} else 'unavailable', http_status=code)
            except Exception:
                finding.update(status='unavailable', detail='Configuration could not be read or parsed within the validation limits.')
    return {'observed_at': datetime.now(timezone.utc).isoformat(), 'configurations': checks, 'limitations': [
        'Static configuration checks only. No cluster changes, token values or raw YAML are returned.',
        'Route matching, inhibition, Secret mounts, CA trust, configuration reload and network delivery are not verified.',
        'A separate user-workload Alertmanager is optional; not_found does not imply platform monitoring is broken.',
        'Host comparison uses this PodPilot request hostname; review proxy aliases if it differs.',
    ]}
