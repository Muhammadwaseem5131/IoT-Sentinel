from correlation import service_rules


def _ports(*ps):
    return [{"port": p, "service": None, "banner": None} for p in ps]


def test_telnet_flagged_high():
    findings = service_rules.evaluate(_ports(23))
    telnet = [f for f in findings if "Telnet" in f["description"]]
    assert telnet and telnet[0]["severity"] == "high" and telnet[0]["weight"] >= 8


def test_clean_https_device_no_cleartext_finding():
    findings = service_rules.evaluate(_ports(443))
    assert not any(f["finding_type"] == "weak_encryption" for f in findings)


def test_http_without_https_flags_cleartext():
    findings = service_rules.evaluate(_ports(80))
    assert any(f["finding_type"] == "weak_encryption" for f in findings)


def test_internet_facing_service_escalates():
    internal = service_rules.evaluate(_ports(23), internet_facing=False)
    external = service_rules.evaluate(_ports(23), internet_facing=True)
    assert not any(f["finding_type"] == "exposure" for f in internal)
    assert any(f["finding_type"] == "exposure" for f in external)


def test_large_attack_surface():
    findings = service_rules.evaluate(_ports(22, 80, 443, 8080, 8443, 9100))
    assert any(f["finding_type"] == "attack_surface" for f in findings)


def test_no_open_ports_no_findings():
    assert service_rules.evaluate([]) == []


def test_multiple_insecure_services():
    findings = service_rules.evaluate(_ports(23, 21, 445, 3389))
    # telnet, ftp, smb, rdp -> at least four insecure-service findings
    assert len([f for f in findings if f["finding_type"] == "insecure_service"]) >= 4
