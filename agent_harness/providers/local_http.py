"""Strict local structured proposals. A proposal is never authorization."""
import http.client
import json
import math
import socket
import threading
import time
from urllib.parse import urlsplit

OPERATIONS = ('read_file', 'write_file', 'api_get', 'api_post')
PROPOSAL_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['done', 'operation', 'resource', 'body'],
    'properties': {
        'done': {'type': 'boolean'},
        'operation': {'type': 'string', 'enum': ['', *OPERATIONS]},
        'resource': {'type': 'string', 'maxLength': 512},
        'body': {'type': 'string', 'maxLength': 32768},
    },
}
MAX_RESPONSE = 65536
MAX_REQUEST = 1048576


class ModelError(ValueError):
    """Safe diagnostics: codes only, never server bodies, prompts or credentials."""
    def __init__(self, code, http_status=None):
        self.code, self.http_status = code, http_status
        super().__init__(code + (f' (HTTP {http_status})' if http_status is not None else ''))


def validate_proposal(proposal):
    if not isinstance(proposal, dict) or set(proposal) != set(PROPOSAL_SCHEMA['required']):
        raise ModelError('proposal_schema')
    if type(proposal['done']) is not bool or any(type(proposal[k]) is not str for k in ['operation', 'resource', 'body']):
        raise ModelError('proposal_schema')
    try:
        if len(proposal['resource'].encode()) > 512 or len(proposal['body'].encode()) > 32768:
            raise ModelError('proposal_schema')
    except UnicodeError:
        raise ModelError('proposal_schema') from None
    if proposal['done']:
        if any(proposal[k] for k in ['operation', 'resource', 'body']):
            raise ModelError('proposal_schema')
    elif (proposal['operation'] not in OPERATIONS or not proposal['resource']
          or (proposal['operation'] in ('read_file', 'api_get') and proposal['body'])):
        raise ModelError('proposal_schema')
    return proposal


def strict_json(raw, code):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-JSON constant')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ModelError(code) from None


class LocalJsonModel:
    def __init__(self, endpoint, model, api_key=None, timeout=60):
        parsed = urlsplit(endpoint)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Only explicit loopback HTTP model endpoints are supported')
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError('Timeout must be between 0 and 300 seconds')
        self.port = parsed.port or 80
        self.path = parsed.path or '/v1/chat/completions'
        self.model, self._api_key, self.timeout = model, api_key, timeout

    def propose(self, messages):
        body = {'model': self.model, 'messages': messages, 'temperature': 0,
                'stream': False, 'max_tokens': 2048,
                'response_format': {'type': 'json_schema', 'json_schema': {
                    'name': 'sentinel_action', 'strict': True, 'schema': PROPOSAL_SCHEMA}}}
        try:
            wire = json.dumps(body, allow_nan=False).encode()
        except (ValueError, TypeError, UnicodeError):
            raise ModelError('request_invalid') from None
        if len(wire) > MAX_REQUEST:
            raise ModelError('request_too_large')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=self.timeout)
        headers = {'Content-Type': 'application/json'}
        if self._api_key:
            headers['Authorization'] = 'Bearer ' + self._api_key
        timer = None
        expired = threading.Event()
        started = time.monotonic()
        try:
            connection.connect()
            sock = connection.sock
            def expire():
                expired.set()
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(0, self.timeout - (time.monotonic() - started)), expire)
            timer.daemon = True
            timer.start()
            connection.request('POST', self.path, wire, headers)
            response = connection.getresponse()
            if response.status != 200:
                raise ModelError('http_error', response.status)
            raw = response.read(MAX_RESPONSE + 1)
            if expired.is_set():
                raise ModelError('timeout')
            if len(raw) > MAX_RESPONSE:
                raise ModelError('response_too_large')
            result = strict_json(raw, 'response_json')
            try:
                choices = result['choices']
                if not isinstance(choices, list) or len(choices) != 1:
                    raise ValueError()
                choice = choices[0]
                if choice.get('finish_reason') != 'stop':
                    raise ModelError('model_incomplete')
                content = choice['message']['content']
                if not isinstance(content, str) or choice['message'].get('tool_calls'):
                    raise ValueError()
            except (KeyError, TypeError, AttributeError, ValueError) as error:
                if isinstance(error, ModelError):
                    raise
                raise ModelError('response_envelope') from None
            return validate_proposal(strict_json(content, 'proposal_json'))
        except ModelError:
            raise
        except (ValueError, UnicodeError):
            raise ModelError('request_invalid') from None
        except (TimeoutError, socket.timeout):
            raise ModelError('timeout') from None
        except (OSError, http.client.HTTPException):
            raise ModelError('timeout' if expired.is_set() else 'transport_error') from None
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            connection.close()
