from correlation import risk_score


def test_score_is_bounded():
    for _ in range(3):
        s = risk_score.compute_risk_score(True, 10.0, True, True)
        assert 0 <= s <= 100
    assert risk_score.compute_risk_score() >= 0


def test_worst_case_is_max():
    assert risk_score.compute_risk_score(
        internet_facing=True, max_cve_score=10.0, default_cred_found=True, weak_encryption=True
    ) == 100


def test_clean_internal_device_is_low():
    s = risk_score.compute_risk_score(internet_facing=False, max_cve_score=None,
                                      default_cred_found=False, weak_encryption=False)
    assert s < 35  # LAN-only, no findings -> low band


def test_exposure_raises_score():
    internal = risk_score.compute_risk_score(internet_facing=False, max_cve_score=7.0)
    external = risk_score.compute_risk_score(internet_facing=True, max_cve_score=7.0)
    assert external > internal


def test_cvss_score_clamped():
    # An out-of-range CVSS must not push the score past its band.
    assert risk_score.compute_risk_score(max_cve_score=99.0) <= 100
    assert risk_score.compute_risk_score(max_cve_score=-5.0) >= 0


def test_severity_labels():
    assert risk_score.cve_severity_label(9.5) == "critical"
    assert risk_score.cve_severity_label(7.5) == "high"
    assert risk_score.cve_severity_label(5.0) == "medium"
    assert risk_score.cve_severity_label(1.0) == "low"
    assert risk_score.cve_severity_label(None) == "low"
