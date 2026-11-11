from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    assert client.get('/health').json()['status'] == 'ok'

def test_dashboard_served():
    r = client.get('/dashboard')
    assert r.status_code == 200 and 'NetSecure AI' in r.text

def test_ai_status_is_deterministic():
    data = client.get('/ai/status').json()
    assert data == {'configured': False, 'mode': 'deterministic_fallback', 'provider_required': False}

def test_chat_explains_open_port():
    data = client.post('/chat', json={'message': 'What does an open port mean?'}).json()
    assert data['model_connected'] is False and 'connection was accepted' in data['reply']

def test_authorization_required():
    assert client.post('/scan', json={'target':'192.168.1.10','ports':[80]}).status_code == 403

def test_public_target_rejected():
    assert client.post('/scan', json={'target':'8.8.8.8','authorized':True,'ports':[53]}).status_code == 403

def test_invalid_report_format():
    r=client.post('/report',json={'target':'192.168.1.10','authorized':True,'ports':[80],'format':'pdf'})
    assert r.status_code == 422

def test_cve_query_validation():
    assert client.get('/cves/search?q=x').status_code == 422
    assert client.get('/cves/search?q=apache&limit=99').status_code == 422

def test_nvd_failure_handled(monkeypatch):
    import app.main as main
    async def fail(*args, **kwargs):
        import httpx
        raise httpx.ConnectError('offline')
    monkeypatch.setattr(main, 'search_cves', fail)
    r=client.get('/cves/search?q=apache')
    assert r.status_code == 503
