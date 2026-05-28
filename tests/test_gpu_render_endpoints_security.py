# SPDX-License-Identifier: MIT

import sqlite3

import pytest
from flask import Flask

from node.gpu_render_endpoints import register_gpu_render_endpoints


ADMIN_KEY = "test-admin-key"


def _create_app(db_path, admin_key=ADMIN_KEY):
    app = Flask(__name__)
    app.config["TESTING"] = True
    register_gpu_render_endpoints(app, str(db_path), admin_key)
    return app


def _init_db(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE balances (
                miner_pk TEXT PRIMARY KEY,
                balance_rtc REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE render_escrow (
                job_id TEXT PRIMARY KEY,
                job_type TEXT,
                from_wallet TEXT,
                to_wallet TEXT,
                amount_rtc REAL,
                status TEXT,
                created_at INTEGER,
                released_at INTEGER,
                escrow_secret_hash TEXT
            )
            """
        )
        conn.execute("INSERT INTO balances (miner_pk, balance_rtc) VALUES (?, ?)", ("victim", 25.0))
        conn.execute("INSERT INTO balances (miner_pk, balance_rtc) VALUES (?, ?)", ("attacker", 0.0))


def _balance(db_path, wallet):
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT balance_rtc FROM balances WHERE miner_pk = ?", (wallet,)).fetchone()[0]


def _escrow_payload():
    return {
        "job_id": "job-1",
        "job_type": "render",
        "from_wallet": "victim",
        "to_wallet": "attacker",
        "amount_rtc": 5,
    }


def test_gpu_escrow_rejects_unauthenticated_wallet_lock(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    response = client.post("/api/gpu/escrow", json=_escrow_payload())

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized - admin key required"}
    assert _balance(db_path, "victim") == 25.0
    assert _balance(db_path, "attacker") == 0.0


def test_gpu_settlement_rejects_unauthenticated_secret_replay(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    created = client.post(
        "/api/gpu/escrow",
        json=_escrow_payload(),
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert created.status_code == 200
    escrow_secret = created.get_json()["escrow_secret"]

    release = client.post(
        "/api/gpu/release",
        json={"job_id": "job-1", "actor_wallet": "victim", "escrow_secret": escrow_secret},
    )

    assert release.status_code == 401
    assert release.get_json() == {"error": "Unauthorized - admin key required"}
    assert _balance(db_path, "victim") == 20.0
    assert _balance(db_path, "attacker") == 0.0


def test_gpu_admin_can_create_and_release_escrow(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    created = client.post(
        "/api/gpu/escrow",
        json=_escrow_payload(),
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert created.status_code == 200
    escrow_secret = created.get_json()["escrow_secret"]

    released = client.post(
        "/api/gpu/release",
        json={"job_id": "job-1", "actor_wallet": "victim", "escrow_secret": escrow_secret},
        headers={"X-Admin-Key": ADMIN_KEY},
    )

    assert released.status_code == 200
    assert released.get_json() == {"ok": True, "status": "released"}
    assert _balance(db_path, "victim") == 20.0
    assert _balance(db_path, "attacker") == 5.0


def test_gpu_admin_endpoints_fail_closed_without_configured_key(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path, admin_key="").test_client()

    response = client.post(
        "/api/gpu/escrow",
        json=_escrow_payload(),
        headers={"X-Admin-Key": ADMIN_KEY},
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Admin key not configured"}
    assert _balance(db_path, "victim") == 25.0


@pytest.mark.parametrize(
    ("path", "headers"),
    [
        ("/api/gpu/attest", {}),
        ("/api/gpu/escrow", {"X-Admin-Key": ADMIN_KEY}),
        ("/api/gpu/release", {"X-Admin-Key": ADMIN_KEY}),
        ("/api/gpu/refund", {"X-Admin-Key": ADMIN_KEY}),
    ],
)
def test_gpu_routes_reject_non_object_json(tmp_path, path, headers):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    response = client.post(path, headers=headers, json=[{"unexpected": "array"}])

    assert response.status_code == 400
    assert response.get_json() == {"error": "JSON object required"}


def test_gpu_escrow_rejects_structured_string_fields(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    payload = _escrow_payload()
    payload["job_id"] = {"structured": "job"}

    response = client.post(
        "/api/gpu/escrow",
        json=payload,
        headers={"X-Admin-Key": ADMIN_KEY},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "job_id must be a string"}
    assert _balance(db_path, "victim") == 25.0


def test_gpu_release_rejects_structured_escrow_secret(tmp_path):
    db_path = tmp_path / "gpu.db"
    _init_db(db_path)
    client = _create_app(db_path).test_client()

    created = client.post(
        "/api/gpu/escrow",
        json=_escrow_payload(),
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert created.status_code == 200

    response = client.post(
        "/api/gpu/release",
        json={"job_id": "job-1", "actor_wallet": "victim", "escrow_secret": ["not", "text"]},
        headers={"X-Admin-Key": ADMIN_KEY},
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "escrow_secret must be a string"}
    assert _balance(db_path, "victim") == 20.0
    assert _balance(db_path, "attacker") == 0.0


def _init_attest_db(db_path):
    """Create DB with gpu_attestations table for attest tests."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gpu_attestations (
                miner_id TEXT PRIMARY KEY,
                gpu_model TEXT,
                vram_gb INTEGER,
                cuda_version TEXT,
                benchmark_score INTEGER,
                price_render_minute REAL,
                price_tts_1k_chars REAL,
                price_stt_minute REAL,
                price_llm_1k_tokens REAL,
                supports_render INTEGER,
                supports_tts INTEGER,
                supports_stt INTEGER,
                supports_llm INTEGER,
                last_attestation INTEGER
            )
            """
        )


def test_gpu_attest_bogus_signature_cannot_overwrite(tmp_path):
    """Regression test: a bogus ed25519 signature must not allow overwriting
    another miner's attestation. This was the v1 bug where _require_miner_signature()
    ran before body parsing and never actually verified the signature.
    """
    from nacl.signing import SigningKey

    db_path = tmp_path / "attest.db"
    _init_attest_db(db_path)
    client = _create_app(db_path).test_client()

    # Create two keypairs: victim (legit) and attacker (bogus)
    victim_sk = SigningKey.generate()
    victim_pk_hex = victim_sk.verify_key.encode().hex()
    attacker_sk = SigningKey.generate()
    attacker_pk_hex = attacker_sk.verify_key.encode().hex()

    import time as _time
    ts = int(_time.time())

    # Victim posts a legitimate attestation with a valid signature
    victim_payload = "attest:" + victim_pk_hex + ":" + str(ts)
    victim_sig = victim_sk.sign(victim_payload.encode()).signature.hex()

    legit = client.post(
        "/api/gpu/attest",
        json={
            "miner_id": victim_pk_hex,
            "gpu_model": "NVIDIA A100",
            "vram_gb": 80,
            "benchmark_score": 9000,
            "price_render_minute": 0.5,
            "price_tts_1k_chars": 0.1,
            "price_stt_minute": 0.2,
            "price_llm_1k_tokens": 0.05,
        },
        headers={
            "X-Miner-Signature": victim_sig,
            "X-Miner-Timestamp": str(ts),
        },
    )
    assert legit.status_code == 200
    assert legit.get_json()["ok"] is True

    # Attacker tries to overwrite victim's attestation using their OWN signature
    # (not the victim's). This MUST fail with 401.
    attacker_payload = "attest:" + victim_pk_hex + ":" + str(ts)
    bogus_sig = attacker_sk.sign(attacker_payload.encode()).signature.hex()

    overwrite = client.post(
        "/api/gpu/attest",
        json={
            "miner_id": victim_pk_hex,
            "gpu_model": "FAKE GPU",
            "vram_gb": 1,
            "benchmark_score": 0,
            "price_render_minute": 0.0,
            "price_tts_1k_chars": 0.0,
            "price_stt_minute": 0.0,
            "price_llm_1k_tokens": 0.0,
        },
        headers={
            "X-Miner-Signature": bogus_sig,
            "X-Miner-Timestamp": str(ts),
        },
    )
    assert overwrite.status_code == 401
    assert overwrite.get_json() == {"error": "Invalid miner signature"}

    # Verify victim's original attestation is unchanged
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT gpu_model FROM gpu_attestations WHERE miner_id = ?",
            (victim_pk_hex,),
        ).fetchone()
    assert row is not None
    assert row[0] == "NVIDIA A100"


def test_gpu_attest_non_pubkey_miner_id_requires_admin(tmp_path):
    """Non-hex miner_id (e.g. 'alice') requires admin key as fallback."""
    db_path = tmp_path / "attest.db"
    _init_attest_db(db_path)
    client = _create_app(db_path).test_client()

    # Without any auth, should fail
    no_auth = client.post(
        "/api/gpu/attest",
        json={"miner_id": "alice", "gpu_model": "GTX 1080"},
    )
    assert no_auth.status_code == 401

    # With admin key, should succeed
    with_admin = client.post(
        "/api/gpu/attest",
        json={"miner_id": "alice", "gpu_model": "GTX 1080"},
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert with_admin.status_code == 200
