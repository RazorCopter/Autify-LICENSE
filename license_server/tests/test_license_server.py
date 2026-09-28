import os
import secrets
import time
from datetime import datetime, timezone

os.environ.setdefault("LICENSE_SHARED_SECRET", "test-shared-secret-with-more-than-32-characters")
os.environ.setdefault("LICENSE_ADMIN_KEY", "test-admin-key-with-more-than-32-characters")
os.environ["LICENSE_ACTIVATE_RATE_LIMIT"] = "100/minute"

from fastapi.testclient import TestClient
from limits.util import parse

from app.crypto import decrypt_payload, encrypt_payload
from app import main


def _request_payload(**values):
    return encrypt_payload({
        **values,
        "timestamp": int(time.time()),
        "request_nonce": secrets.token_urlsafe(24),
    })


def test_activation_validation_binding_and_revocation(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    main.limiter.reset()
    with TestClient(main.app) as client:
        headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}
        generated = client.post("/v1/admin/licenses", headers=headers, json={"plan": "12M", "quantity": 1})
        assert generated.status_code == 200
        code = generated.json()["codes"][0]

        activated = client.post("/v1/activate", json=_request_payload(code=code, instance_id="instance-one-12345"))
        assert activated.status_code == 200
        activation = decrypt_payload(activated.json(), validate_freshness=False)
        assert activation["valid"] is True
        assert activation["plan"] == "12M"
        assert activation["license_token"] != main.code_hash(code)

        reused = client.post("/v1/activate", json=_request_payload(code=code, instance_id="instance-two-12345"))
        assert reused.status_code == 409

        validated = client.post("/v1/validate", json=_request_payload(
            license_token=activation["license_token"], instance_id="instance-one-12345"))
        assert validated.status_code == 200
        assert decrypt_payload(validated.json(), validate_freshness=False)["valid"] is True

        replay_envelope = _request_payload(
            license_token=activation["license_token"], instance_id="instance-one-12345")
        assert client.post("/v1/validate", json=replay_envelope).status_code == 200
        assert client.post("/v1/validate", json=replay_envelope).status_code == 409

        revoke = client.post("/v1/admin/licenses/revoke", headers=headers, json={"code": code})
        assert revoke.status_code == 200
        revoked = client.post("/v1/validate", json=_request_payload(
            license_token=activation["license_token"], instance_id="instance-one-12345"))
        assert revoked.status_code == 200
        invalid = decrypt_payload(revoked.json(), validate_freshness=False)
        assert invalid["valid"] is False
        assert invalid["reason"] == "revoked"


def test_activate_rate_limit_returns_429(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    main.limiter.reset()

    route_key = f"{main.activate.__module__}.{main.activate.__name__}"
    limit = main.limiter._route_limits[route_key][0]
    original_limit = limit.limit
    limit.limit = parse("1/minute")
    unknown_code = main.generate_code("1M")

    try:
        with TestClient(main.app) as client:
            first = client.post(
                "/v1/activate",
                json=_request_payload(
                    code=unknown_code,
                    instance_id="rate-limit-instance",
                ),
            )
            second = client.post(
                "/v1/activate",
                json=_request_payload(
                    code=unknown_code,
                    instance_id="rate-limit-instance",
                ),
            )

        assert first.status_code == 404
        assert second.status_code == 429
    finally:
        limit.limit = original_limit
        main.limiter.reset()


def test_add_months_uses_calendar_months():
    assert main.add_months(datetime(2024, 1, 31, tzinfo=timezone.utc), 1) == datetime(
        2024, 2, 29, tzinfo=timezone.utc
    )
    assert main.add_months(datetime(2025, 3, 31, tzinfo=timezone.utc), 1) == datetime(
        2025, 4, 30, tzinfo=timezone.utc
    )


def test_legacy_token_remains_valid_during_migration(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    with TestClient(main.app) as client:
        headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}
        code = client.post(
            "/v1/admin/licenses", headers=headers, json={"plan": "1M", "quantity": 1}
        ).json()["codes"][0]
        legacy_token = main.code_hash(code)
        now = datetime.now(timezone.utc).isoformat()
        with main.db() as connection:
            connection.execute(
                "UPDATE licenses SET instance_id = ?, activated_at = ?, expires_at = ?, token_hash = NULL WHERE code_hash = ?",
                ("legacy-instance-12345", now, None, legacy_token),
            )

        response = client.post(
            "/v1/validate",
            json=_request_payload(
                license_token=legacy_token, instance_id="legacy-instance-12345"
            ),
        )
        assert response.status_code == 200
        assert decrypt_payload(response.json(), validate_freshness=False)["valid"] is True

def test_lifetime_has_no_expiry(tmp_path):
    main.DB_PATH = tmp_path / "lifetime.db"
    with TestClient(main.app) as client:
        headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}
        response = client.post("/v1/admin/licenses", headers=headers, json={"plan": "LIFE"})
        code = response.json()["codes"][0]
        activated = client.post("/v1/activate", json=_request_payload(code=code, instance_id="lifetime-instance"))
        payload = decrypt_payload(activated.json(), validate_freshness=False)
        assert payload["valid"] is True
        assert payload["expires_at"] is None