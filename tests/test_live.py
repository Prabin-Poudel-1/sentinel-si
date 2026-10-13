"""Local HTTP and gateway regressions; no remote services or real credentials."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_harness.live import ModelAgent, verify_audit
from agent_harness.providers.local_http import LocalJsonModel, ModelError, validate_proposal
from agent_harness.supervisor import Supervisor

ACTION = {'done': False, 'operation': 'read_file', 'resource': 'README.md', 'body': ''}
DONE = {'done': True, 'operation': '', 'resource': '', 'body': ''}


@pytest.mark.parametrize('proposal', [ACTION, DONE])
def test_valid(proposal):
    assert validate_proposal(proposal) == proposal


@pytest.mark.parametrize('proposal', [
    {'done': False, 'action': ACTION, 'next_action': ACTION}, [ACTION, ACTION],
    {k: v for k, v in ACTION.items() if k != 'body'},
    {**ACTION, 'approval': 'SYNTHETIC'}, {**ACTION, 'body': None},
    {**ACTION, 'done': 0}, {**ACTION, 'resource': []}, {**ACTION, 'operation': 'shell'},
    {**ACTION, 'body': 'invalid read argument'}, {**DONE, 'resource': 'README.md'},
    {**ACTION, 'operation': ''}, {**ACTION, 'resource': ''},
    {**ACTION, 'operation': 'write_file', 'body': 'x' * 32769},
    {**ACTION, 'resource': 'x' * 513}, {**ACTION, 'body': '\ud800'},
    *[{k: v for k, v in ACTION.items() if k != field} for field in ['done', 'operation', 'resource']],
    *[{**ACTION, field: None} for field in ['done', 'operation', 'resource']],
])
def test_invalid_proposals_never_reach_gateway(proposal):
    class Provider:
        def propose(self, _):
            return proposal
    class Gateway:
        def call(self, *args):
            pytest.fail('Invalid proposal reached gateway')
    result = ModelAgent(Provider(), Gateway()).run('synthetic')
    assert not result['finished'] and result['reason'] == 'proposal_schema'
    assert result['events'] == []


def envelope(content, finish='stop'):
    return json.dumps({'choices': [{'finish_reason': finish, 'message': {'content': content}}]}).encode()


@pytest.fixture
def endpoint():
    config = {'status': 200, 'raw': envelope(json.dumps(ACTION)), 'delay': 0}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            config['request'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            time.sleep(config['delay'])
            self.send_response(config['status'])
            self.send_header('Content-Length', str(len(config['raw'])))
            self.end_headers()
            try:
                self.wfile.write(config['raw'])
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}/v1/chat/completions', config
    server.shutdown()
    server.server_close()
    thread.join()


def test_schema_wire_and_completion(endpoint):
    url, config = endpoint
    config['raw'] = envelope(json.dumps(DONE))
    assert LocalJsonModel(url, 'synthetic').propose([]) == DONE
    wire = config['request']
    assert wire['stream'] is False
    schema = wire['response_format']['json_schema']
    assert schema['strict'] is True and schema['schema']['additionalProperties'] is False
    assert set(schema['schema']['required']) == set(ACTION)


@pytest.mark.parametrize('status,raw,code', [
    (503, b'SYNTHETIC-SECRET', 'http_error'), (302, b'', 'http_error'),
    (200, b'not JSON SYNTHETIC-SECRET', 'response_json'),
    (200, envelope('not JSON SYNTHETIC-SECRET'), 'proposal_json'),
    (200, envelope('{"done":true,"done":false}'), 'proposal_json'),
    (200, b'{}', 'response_envelope'), (200, b'x' * 65537, 'response_too_large'),
    (200, envelope(json.dumps(ACTION), 'length'), 'model_incomplete'),
    (200, envelope(json.dumps({'action': ACTION})), 'proposal_schema'),
    (200, b'{"choices":[],"choices":[]}', 'response_json'),
], ids=lambda v: f"payload-{len(v)}-bytes" if isinstance(v, bytes) else None)
def test_diagnostics_are_distinct_and_redacted(endpoint, status, raw, code):
    url, config = endpoint
    config.update(status=status, raw=raw)
    with pytest.raises(ModelError) as error:
        LocalJsonModel(url, 'synthetic').propose([])
    assert error.value.code == code
    assert 'SYNTHETIC-SECRET' not in str(error.value)
    if code == 'http_error':
        assert error.value.http_status == status


def test_timeout(endpoint):
    url, config = endpoint
    config['delay'] = .25
    with pytest.raises(ModelError) as error:
        LocalJsonModel(url, 'synthetic', timeout=.05).propose([])
    assert error.value.code == 'timeout'


def test_request_bound_and_invalid_timeout(endpoint):
    url, config = endpoint
    with pytest.raises(ModelError, match='request_too_large'):
        LocalJsonModel(url, 'synthetic').propose([{'content': 'x' * 1048576}])
    assert 'request' not in config
    for timeout in [0, -1, 301, float('nan')]:
        with pytest.raises(ValueError):
            LocalJsonModel(url, 'synthetic', timeout=timeout)


class Sequence:
    def __init__(self, proposals):
        self.proposals = iter(proposals)
        self.messages = []
    def propose(self, messages):
        self.messages = list(messages)
        return next(self.proposals)


def test_injected_outputs_unauthorized_actions_and_audit():
    provider = Sequence([{**ACTION, 'resource': 'docs/guide.md'},
                         {**ACTION, 'resource': 'secrets/demo.txt'},
                         {**ACTION, 'operation': 'api_post', 'resource': 'sim:attacker', 'body': 'SYNTHETIC'},
                         {**ACTION, 'operation': 'write_file', 'resource': 'reports/summary.md', 'body': 'safe summary'}, DONE])
    with Supervisor() as controller:
        result = ModelAgent(provider, controller.gateway).run('synthetic')
        assert verify_audit(controller, result)['audit_verified']
    assert result['finished'] and [e['decision'] for e in result['events']] == ['ALLOW', 'DENY', 'DENY', 'ALLOW']
    assert 'SYSTEM OVERRIDE' in json.dumps(provider.messages)
    assert 'SYSTEM OVERRIDE' not in json.dumps(result)
    assert result['events'][1]['observed_event_ids'] == [result['events'][0]['event_id']]
    assert 'safe summary' not in json.dumps(result)


def test_step_limit_and_completion_without_actions():
    with Supervisor() as controller:
        result = ModelAgent(Sequence([ACTION, ACTION]), controller.gateway).run('synthetic', max_steps=2)
        assert result['reason'] == 'step_limit' and len(result['events']) == 2
        assert verify_audit(controller, result)['audit_verified']
    assert ModelAgent(Sequence([DONE]), None).run('synthetic')['events'] == []


def test_gateway_failure_has_unknown_outcome_and_no_retry():
    from agent_harness.gateway import GatewayUnavailable
    class Gateway:
        def call(self, *args):
            raise GatewayUnavailable('closed')
    result = ModelAgent(Sequence([ACTION]), Gateway()).run('synthetic')
    assert result['reason'] == 'gateway_unavailable' and result['events'][0]['executed'] is None


def test_transport_error_is_redacted(monkeypatch):
    import http.client
    def fail(_):
        raise OSError('SYNTHETIC-CONNECTION-DETAIL')
    monkeypatch.setattr(http.client.HTTPConnection, 'connect', fail)
    with pytest.raises(ModelError) as error:
        LocalJsonModel('http://127.0.0.1:11434/v1/chat/completions', 'synthetic').propose([])
    assert str(error.value) == 'transport_error'


def test_provider_error_preserves_previous_events_and_stops():
    class Provider:
        calls = 0
        def propose(self, messages):
            self.calls += 1
            if self.calls == 1:
                return ACTION
            raise ModelError('proposal_json')
    with Supervisor() as controller:
        result = ModelAgent(Provider(), controller.gateway).run('synthetic')
        assert result['reason'] == 'proposal_json' and len(result['events']) == 1
        assert verify_audit(controller, result)['audit_verified']


def test_invalid_auth_header_cannot_leak_secret(endpoint):
    url, _ = endpoint
    with pytest.raises(ModelError) as error:
        LocalJsonModel(url, 'synthetic', api_key='SYNTHETIC-SECRET\ninvalid').propose([])
    assert str(error.value) == 'request_invalid'
