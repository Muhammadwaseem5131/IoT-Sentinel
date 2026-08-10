WEIGHTS = {
    "exposure": 30,
    "severity": 40,
    "auth": 20,
    "encryption": 10,
}


def compute_risk_score(
    internet_facing: bool = False,
    max_cve_score: float | None = None,
    default_cred_found: bool = False,
    weak_encryption: bool = False,
    weak_encryption_partial: bool = False,
) -> int:
    """0-100 weighted risk score per the design doc's formula."""
    exposure_factor = 1.0 if internet_facing else 0.4
    severity = 0.0
    if max_cve_score is not None:
        severity = min(max(max_cve_score, 0.0), 10.0) / 10.0
    auth = 1.0 if default_cred_found else 0.0
    encryption = 0.0
    if weak_encryption:
        encryption = 1.0
    elif weak_encryption_partial:
        encryption = 0.5

    score = (
        WEIGHTS["exposure"] * exposure_factor
        + WEIGHTS["severity"] * severity
        + WEIGHTS["auth"] * auth
        + WEIGHTS["encryption"] * encryption
    )
    return int(min(max(round(score), 0), 100))


def severity_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def cve_severity_label(cvss_score: float | None) -> str:
    if cvss_score is None:
        return "low"
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    return "low"
