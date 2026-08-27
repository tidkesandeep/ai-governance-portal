from datetime import UTC, datetime, timedelta

from aigov.domains.evidence.service import assess_controls, reject_upload


class _System:
    current_version_id = "ver_current"
    environment = "production"
    registration = {"usesCustomerDecision": True}


class _Assessment:
    risk_band = "HIGH"


class _Artifact:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "evd_1")
        self.evidence_type = kwargs["evidence_type"]
        self.bound_version_id = kwargs.get("bound_version_id", "ver_current")
        self.verification_status = kwargs.get("verification_status", "VERIFIED")
        self.collected_at = kwargs.get("collected_at", datetime.now(UTC))
        self.sha256 = kwargs.get("sha256", "sha256:abc")


def test_unknown_when_missing() -> None:
    results = assess_controls(_System(), _Assessment(), [])
    statuses = {item.control_id: item.status for item in results}
    assert statuses["CTRL-ML-PERF-001"] == "UNKNOWN"
    assert statuses["CTRL-FAIRNESS-001"] == "UNKNOWN"
    assert statuses["CTRL-MODEL-CARD-001"] == "UNKNOWN"


def test_stale_when_older_than_max_age() -> None:
    old = datetime.now(UTC) - timedelta(days=40)
    artifacts = [
        _Artifact(evidence_type="EVALUATION_RUN", collected_at=old),
        _Artifact(id="evd_2", evidence_type="MODEL_CARD"),
        _Artifact(id="evd_3", evidence_type="FAIRNESS_EVALUATION"),
    ]
    results = assess_controls(_System(), _Assessment(), artifacts)
    by_type = {item.evidence_type: item.status for item in results}
    assert by_type["EVALUATION_RUN"] == "STALE"
    assert by_type["MODEL_CARD"] == "PASS"


def test_wrong_version_is_unknown() -> None:
    artifacts = [_Artifact(evidence_type="EVALUATION_RUN", bound_version_id="ver_old")]
    results = assess_controls(_System(), _Assessment(), artifacts)
    eval_control = next(item for item in results if item.evidence_type == "EVALUATION_RUN")
    assert eval_control.status == "UNKNOWN"
    assert "previous asset version" in eval_control.reason


def test_reject_eicar_and_empty() -> None:
    assert reject_upload(b"", "MODEL_CARD", 100) == "empty evidence is not allowed"
    payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    assert reject_upload(payload, "MODEL_CARD", 10_000) == "evidence failed malware screening"
    assert reject_upload(b"ok", "NOT_A_TYPE", 100) == "unsupported evidence type"
