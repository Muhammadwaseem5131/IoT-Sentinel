from correlation import default_creds


def test_known_creds_by_vendor():
    creds = default_creds.known_default_creds("Hikvision Digital", None)
    assert ("admin", "12345") in creds


def test_known_creds_by_type():
    creds = default_creds.known_default_creds(None, "camera")
    assert ("admin", "admin") in creds


def test_creds_deduplicated():
    # vendor 'tp-link' + type 'router' overlap on ('admin','admin'); no dupes.
    creds = default_creds.known_default_creds("TP-Link", "router")
    assert len(creds) == len(set(creds))


def test_unknown_device_has_no_creds():
    assert default_creds.known_default_creds("SomeRandomVendor", "toaster") == []


def test_cred_test_allowed():
    assert default_creds.cred_test_allowed("http")
    assert default_creds.cred_test_allowed("HTTPS")
    assert not default_creds.cred_test_allowed("mqtt")
    assert not default_creds.cred_test_allowed(None)


def test_http_check_skips_when_not_challenged(monkeypatch):
    class Resp:
        status_code = 200  # open page, no auth challenge
    monkeypatch.setattr(default_creds.requests, "get", lambda *a, **k: Resp())
    assert default_creds.http_default_cred_check("1.2.3.4", 80, "http", [("admin", "admin")]) is None


def test_http_check_returns_accepted_pair(monkeypatch):
    calls = {"n": 0}

    class Resp:
        def __init__(self, code):
            self.status_code = code

    def fake_get(url, **kwargs):
        if "auth" not in kwargs:
            return Resp(401)  # challenge on the unauthenticated probe
        calls["n"] += 1
        return Resp(200)  # any credentials accepted

    monkeypatch.setattr(default_creds.requests, "get", fake_get)
    hit = default_creds.http_default_cred_check("1.2.3.4", 80, "http", [("admin", "admin")])
    assert hit == ("admin", "admin")
