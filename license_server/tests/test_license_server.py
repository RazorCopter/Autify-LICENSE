import os
import secrets
import sqlite3
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
        assert reused.json() == {
            "detail": (
                "Licenza già attiva su un'altra installazione. "
                "Disattivarla dalla precedente installazione prima di procedere."
            )
        }

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


def test_deactivation_authorization_and_reactivation(tmp_path):
    main.DB_PATH = tmp_path / "deactivation.db"
    main.limiter.reset()
    with TestClient(main.app) as client:
        headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}
        generated = client.post("/v1/admin/licenses", headers=headers, json={"plan": "12M", "quantity": 1})
        assert generated.status_code == 200
        code = generated.json()["codes"][0]

        activated = client.post(
            "/v1/activate",
            json=_request_payload(code=code, instance_id="instance-one-12345"),
        )
        assert activated.status_code == 200
        activation = decrypt_payload(activated.json(), validate_freshness=False)
        token = activation["license_token"]

        unauthorized = client.post(
            "/v1/deactivate",
            json=_request_payload(
                license_token=token,
                instance_id="instance-two-12345",
            ),
        )
        assert unauthorized.status_code == 200
        unauthorized_payload = decrypt_payload(unauthorized.json(), validate_freshness=False)
        assert unauthorized_payload["valid"] is False
        assert unauthorized_payload["reason"] == "unauthorized"

        deactivated = client.post(
            "/v1/deactivate",
            json=_request_payload(
                license_token=token,
                instance_id="instance-one-12345",
            ),
        )
        assert deactivated.status_code == 200
        deactivation = decrypt_payload(deactivated.json(), validate_freshness=False)
        assert deactivation["valid"] is True
        assert deactivation["reason"] == "deactivated"

        invalid_token = client.post(
            "/v1/deactivate",
            json=_request_payload(
                license_token=token,
                instance_id="instance-one-12345",
            ),
        )
        assert invalid_token.status_code == 200
        invalid_token_payload = decrypt_payload(invalid_token.json(), validate_freshness=False)
        assert invalid_token_payload["valid"] is False
        assert invalid_token_payload["reason"] == "unauthorized"

        reactivated = client.post(
            "/v1/activate",
            json=_request_payload(code=code, instance_id="instance-two-12345"),
        )
        assert reactivated.status_code == 200
        reactivation = decrypt_payload(reactivated.json(), validate_freshness=False)
        assert reactivation["valid"] is True
        assert reactivation["license_token"] != token

        revalidated = client.post(
            "/v1/validate",
            json=_request_payload(
                license_token=reactivation["license_token"],
                instance_id="instance-two-12345",
            ),
        )
        assert revalidated.status_code == 200
        revalidation = decrypt_payload(revalidated.json(), validate_freshness=False)
        assert revalidation["valid"] is True


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


def test_admin_can_reveal_new_license_without_exposing_code_in_lists(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}

    with TestClient(main.app) as client:
        generated = client.post(
            "/v1/admin/licenses",
            headers=headers,
            json={"plan": "6M", "quantity": 1, "customer": "Example SpA"},
        )
        assert generated.status_code == 200
        code = generated.json()["codes"][0]
        suffix = code[-6:]

        listed = client.get("/v1/admin/licenses", headers=headers)
        assert listed.status_code == 200
        license_data = listed.json()["licenses"][0]
        assert license_data["code_available"] is True
        assert "code" not in license_data
        assert code not in listed.text

        detail = client.get(f"/v1/admin/licenses/{suffix}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["code_available"] is True
        assert "code" not in detail.json()

        revealed = client.get(f"/v1/admin/licenses/{suffix}/code", headers=headers)
        assert revealed.status_code == 200
        assert revealed.json() == {"code": code}

    with sqlite3.connect(main.DB_PATH) as connection:
        stored = connection.execute(
            "SELECT code_hash, encrypted_code FROM licenses WHERE code_suffix = ?", (suffix,)
        ).fetchone()
    assert stored[0] == main.code_hash(code)
    assert stored[1] is not None
    assert code not in stored[1]


def test_code_reveal_requires_admin_authentication(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}

    with TestClient(main.app) as client:
        generated = client.post("/v1/admin/licenses", headers=headers, json={"plan": "1M", "quantity": 1})
        suffix = generated.json()["codes"][0][-6:]
        assert client.get(f"/v1/admin/licenses/{suffix}/code").status_code == 401


def test_historical_license_code_is_unavailable_after_migration(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}
    code = main.generate_code("LIFE")
    with sqlite3.connect(main.DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE licenses (
                code_hash TEXT PRIMARY KEY,
                code_suffix TEXT NOT NULL,
                plan TEXT NOT NULL,
                customer TEXT,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                expires_at TEXT,
                instance_id TEXT,
                revoked_at TEXT,
                token_hash TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO licenses(code_hash, code_suffix, plan, customer, created_at) VALUES (?, ?, ?, ?, ?)",
            (main.code_hash(code), code[-6:], "LIFE", "Storico", datetime.now(timezone.utc).isoformat()),
        )

    with TestClient(main.app) as client:
        with sqlite3.connect(main.DB_PATH) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(licenses)")}
        assert "encrypted_code" in columns
        detail = client.get(f"/v1/admin/licenses/{code[-6:]}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["code_available"] is False
        unavailable = client.get(f"/v1/admin/licenses/{code[-6:]}/code", headers=headers)
        assert unavailable.status_code == 404
        assert unavailable.json()["detail"] == "Codice licenza non disponibile"


def test_license_deletion_and_active_force_guard(tmp_path):
    main.DB_PATH = tmp_path / "licenses.db"
    main.limiter.reset()
    headers = {"X-License-Admin-Key": os.environ["LICENSE_ADMIN_KEY"]}

    with TestClient(main.app) as client:
        generated = client.post("/v1/admin/licenses", headers=headers, json={"plan": "12M", "quantity": 2})
        first_code, active_code = generated.json()["codes"]

        unauthorized = client.delete(f"/v1/admin/licenses/{first_code[-6:]}")
        assert unauthorized.status_code == 401
        deleted = client.delete(f"/v1/admin/licenses/{first_code[-6:]}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json() == {"status": "deleted"}
        assert client.get(f"/v1/admin/licenses/{first_code[-6:]}", headers=headers).status_code == 404

        activated = client.post(
            "/v1/activate",
            json=_request_payload(code=active_code, instance_id="active-delete-instance"),
        )
        assert activated.status_code == 200
        guarded = client.delete(f"/v1/admin/licenses/{active_code[-6:]}", headers=headers)
        assert guarded.status_code == 409
        assert client.get(f"/v1/admin/licenses/{active_code[-6:]}", headers=headers).status_code == 200

        forced = client.delete(f"/v1/admin/licenses/{active_code[-6:]}?force=true", headers=headers)
        assert forced.status_code == 200
        assert forced.json() == {"status": "deleted"}
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


def test_admin_dashboard_session_listing_stats_and_actions(tmp_path, monkeypatch):
    main.DB_PATH = tmp_path / "admin-dashboard.db"
    main.ADMIN_SESSIONS.clear()
    main.ADMIN_LOGIN_ATTEMPTS.clear()
    monkeypatch.setenv("LICENSE_ADMIN_COOKIE_SECURE", "false")

    with TestClient(main.app) as client:
        dashboard = client.get("/admin/")
        assert dashboard.status_code == 200
        assert "Gestione licenze" in dashboard.text

        assert client.get("/v1/admin/licenses").status_code == 401
        invalid_login = client.post("/v1/admin/session", json={"admin_key": "wrong-key"})
        assert invalid_login.status_code == 401

        login = client.post(
            "/v1/admin/session",
            json={"admin_key": os.environ["LICENSE_ADMIN_KEY"]},
        )
        assert login.status_code == 200
        assert login.json()["authenticated"] is True
        assert login.cookies.get(main.ADMIN_SESSION_COOKIE)

        generated = client.post(
            "/v1/admin/licenses",
            json={"plan": "6M", "customer": "Azienda Demo", "quantity": 1},
        )
        assert generated.status_code == 200
        code = generated.json()["codes"][0]
        suffix = code[-6:]

        listed = client.get("/v1/admin/licenses", params={"customer": "Demo", "plan": "6M"})
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        assert listed.json()["licenses"][0] == {
            "code_suffix": suffix,
            "plan": "6M",
            "customer": "Azienda Demo",
            "created_at": listed.json()["licenses"][0]["created_at"],
            "activated_at": None,
            "expires_at": None,
            "instance_id": None,
            "revoked_at": None,
            "status": "not_activated",
            "code_available": True,
        }
        assert client.get(f"/v1/admin/licenses/{suffix}").status_code == 200
        assert client.get("/v1/admin/stats").json() == {
            "total": 1,
            "not_activated": 1,
            "active": 0,
            "expired": 0,
            "revoked": 0,
        }

        revoked = client.post(f"/v1/admin/licenses/{suffix}/revoke")
        assert revoked.status_code == 200
        assert client.get("/v1/admin/stats").json()["revoked"] == 1

        released = client.post(f"/v1/admin/licenses/{suffix}/release")
        assert released.status_code == 200
        assert client.get(f"/v1/admin/licenses/{suffix}").json()["status"] == "not_activated"

        logout = client.delete("/v1/admin/session")
        assert logout.status_code == 200
        assert client.get("/v1/admin/stats").status_code == 401