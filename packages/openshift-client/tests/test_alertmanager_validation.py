import base64
import json

import httpx
import pytest
import yaml

from podpilot_openshift.alertmanager_validation import validate_alertmanager_configuration


def config(token='private-token-value'):
    return {'receivers': [{'name': 'podpilot', 'webhook_configs': [{
        'url': 'https://podpilot.example/api/v1/incident-webhooks/source',
        'send_resolved': True, 'http_config': {'authorization': {'type': 'Bearer', 'credentials': token}},
    }]}], 'route': {'receiver': 'podpilot'}}


def validate(document, extra=None):
    def handler(request):
        assert request.method == 'GET'
        if request.url.path.endswith('/alertmanager-main'):
            return httpx.Response(200, json={'data': {'alertmanager.yaml': base64.b64encode(yaml.safe_dump(document).encode()).decode()}})
        if extra and request.url.path.endswith('/receiver-token'):
            return httpx.Response(200, json={'data': {'token': base64.b64encode(extra.encode()).decode()}})
        return httpx.Response(404)
    return validate_alertmanager_configuration('http://broker/cap/', source_id='source',
        expected_token='private-token-value', public_host='podpilot.example', transport=httpx.MockTransport(handler))


def test_inline_token_and_optional_user_workload_return_only_findings():
    result = validate(config())
    assert result['configurations'][0]['status'] == 'static_checks_passed'
    assert result['configurations'][1]['status'] == 'not_found'
    assert 'private-token-value' not in json.dumps(result)


def test_wrong_token_fails_and_standard_secret_mount_can_be_checked():
    result = validate(config('different-private-value'))
    assert result['configurations'][0]['checks'][0]['token_matches'] is False
    assert 'different-private-value' not in json.dumps(result)
    document = config()
    document['receivers'][0]['webhook_configs'][0]['http_config']['authorization'] = {
        'credentials_file': '/etc/alertmanager/secrets/receiver-token/token'}
    result = validate(document, extra='private-token-value')
    assert result['configurations'][0]['checks'][0]['token_matches'] is True
    assert 'mount not verified' in result['configurations'][0]['checks'][0]['token_source']


@pytest.mark.parametrize('status,expected', [(403, 'denied'), (500, 'unavailable')])
def test_read_failures_do_not_expose_server_bodies(status, expected):
    result = validate_alertmanager_configuration('http://broker/cap/', source_id='source',
        expected_token='private-token-value', public_host='podpilot.example',
        transport=httpx.MockTransport(lambda _: httpx.Response(status, text='private-server-message')))
    assert all(c['status'] == expected for c in result['configurations'])
    assert 'private-server-message' not in json.dumps(result)


def test_unrecognized_file_path_remains_unknown_without_reading_it():
    document = config()
    document['receivers'][0]['webhook_configs'][0]['http_config']['authorization'] = {
        'credentials_file': '/etc/arbitrary/private-file'}
    result = validate(document)
    assert result['configurations'][0]['checks'][0]['token_matches'] is None
    assert result['configurations'][0]['status'] == 'review_required'
