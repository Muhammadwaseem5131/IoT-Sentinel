from correlation import kev


def test_is_known_exploited(monkeypatch):
    monkeypatch.setattr(kev, "_KEV_SET", {"CVE-2021-36260", "CVE-2017-9765"})
    assert kev.is_known_exploited("CVE-2021-36260")
    assert not kev.is_known_exploited("CVE-1999-0001")
    assert not kev.is_known_exploited(None)
    assert not kev.is_known_exploited("")


def test_empty_catalog_no_enrichment(monkeypatch):
    monkeypatch.setattr(kev, "_KEV_SET", set())
    assert not kev.is_known_exploited("CVE-2021-36260")
