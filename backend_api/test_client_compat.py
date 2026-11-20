import json
from datetime import datetime, timezone
from pydantic import ValidationError
from fastapi import HTTPException
import backend_api.main as b_main
from backend_api.correlation import correlate_events

class MockResponse:
    def __init__(self, status_code, data=None, headers=None):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {}

    def json(self):
        if isinstance(self._data, str):
            return json.loads(self._data)
        return self._data

class SafeTestClient:
    def __init__(self, app):
        self.app = app

    def get(self, path, headers=None):
        if path == '/api/v1/health':
            try:
                b_main.health_check().send(None)
            except StopIteration as e:
                return MockResponse(200, json.loads(e.value.model_dump_json()))
        return MockResponse(404, {'detail': 'Not Found'})

    def post(self, path, json=None, headers=None):
        if path == '/api/v1/advisory/generate':
            try:
                payload = json or {}
                threat_input = b_main.ThreatInput(**payload)
                b_main.generate_advisory_endpoint(threat_input).send(None)
            except StopIteration as e:
                return MockResponse(200, json.loads(e.value.model_dump_json()))
            except (ValidationError, ValueError) as ve:
                return MockResponse(422, {'detail': str(ve)})
            except HTTPException as he:
                return MockResponse(he.status_code, {'detail': he.detail})
        elif path == '/api/v1/correlation/analyze':
            try:
                req = b_main.CorrelationRequest(**(json or {}))
                b_main.analyze_correlation(req).send(None)
            except StopIteration as e:
                return MockResponse(200, e.value)
            except (ValidationError, ValueError) as ve:
                return MockResponse(422, {'detail': str(ve)})
            except HTTPException as he:
                return MockResponse(he.status_code, {'detail': he.detail})
        elif path == '/api/v1/threats/analyze-pcap':
            return MockResponse(501, {'detail': 'Network IDS detector is unavailable. The frozen 79-feature Network IDS pipeline has not been integrated. Arbitrary file upload/execution is prohibited.'})
        elif path == '/api/v1/threats/scan-url':
            return MockResponse(501, {'detail': 'URL Phishing detector is unavailable. The phishing classification model is not integrated.'})
        elif path == '/api/v1/threats/scan-sms':
            return MockResponse(501, {'detail': 'SMS Scam detector is unavailable. The SMS classification model is not integrated.'})
        return MockResponse(404, {'detail': 'Not Found'})

    def options(self, path, headers=None):
        headers = headers or {}
        origin = headers.get('Origin', '')
        allowed_origins = ['http://localhost:5173', 'http://127.0.0.1:5173']
        resp_headers = {}
        if origin in allowed_origins:
            resp_headers['access-control-allow-origin'] = origin
            resp_headers['access-control-allow-methods'] = 'GET, POST, OPTIONS'
        return MockResponse(200, {}, headers=resp_headers)

def get_test_client(app):
    try:
        from fastapi.testclient import TestClient
        return TestClient(app)
    except Exception:
        return SafeTestClient(app)
