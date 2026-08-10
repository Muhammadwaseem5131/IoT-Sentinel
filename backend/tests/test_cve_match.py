from correlation import cve_match


def test_parse_banner_splits_name_and_version():
    assert cve_match._parse_banner("lighttpd 1.4.35") == ("lighttpd", "1.4.35")
    assert cve_match._parse_banner("Mosquitto 1.5.7") == ("Mosquitto", "1.5.7")
    assert cve_match._parse_banner(None) == ("", None)
    assert cve_match._parse_banner("") == ("", None)


def test_relevant_filters_by_token():
    assert cve_match._relevant({"description": "flaw in lighttpd server"}, ["lighttpd"])
    assert not cve_match._relevant({"description": "flaw in nginx"}, ["lighttpd"])
    # empty token list keeps everything
    assert cve_match._relevant({"description": "anything"}, [])


def test_match_cves_uses_product_and_filters(monkeypatch):
    fake = [
        {"cve_id": "CVE-1", "base_score": 9.0, "description": "RCE in lighttpd web server"},
        {"cve_id": "CVE-2", "base_score": 4.0, "description": "unrelated nginx bug"},
        {"cve_id": "CVE-3", "base_score": 7.0, "description": "lighttpd path traversal"},
    ]
    monkeypatch.setattr(cve_match, "_query", lambda kw: fake)
    out = cve_match.match_cves("http", "lighttpd 1.4.35")
    ids = [c["cve_id"] for c in out]
    assert "CVE-2" not in ids  # filtered: doesn't mention lighttpd
    assert ids == ["CVE-1", "CVE-3"]  # sorted by score desc


def test_generic_service_without_product_returns_empty():
    # No product banner + a service with no safe keyword -> no noisy guess.
    assert cve_match.match_cves("http", None) == []
    assert cve_match.match_cves(None, None) == []
