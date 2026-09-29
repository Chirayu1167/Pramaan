"""Firebase Admin SDK Auth & Session Management for Pramaan.

Handles Google Auth & Email/Password token verification, session tracking,
and Firestore session persistence to enforce robust operational user security.
"""
import hashlib
import json
import os
import time
import uuid
from typing import Optional, Tuple, Dict, Any

import firebase_admin
from firebase_admin import credentials, auth, firestore

CREDENTIAL_FILE = os.path.join(
    os.path.dirname(__file__),
    "pramaan-1-firebase-adminsdk-fbsvc-4cc3aede82.json"
)

_firebase_app = None
_db = None


def get_firestore_client():
    """Initializes and returns the Firestore client using the Service Account or Env Var."""
    global _firebase_app, _db
    if _db is not None:
        return _db

    if not firebase_admin._apps:
        # 1. Try env var containing JSON string (Render / Cloud deployment)
        env_cred = os.getenv("FIREBASE_ADMIN_CREDENTIALS")
        if env_cred:
            try:
                cred_dict = json.loads(env_cred)
                cred = credentials.Certificate(cred_dict)
                _firebase_app = firebase_admin.initialize_app(cred, {"projectId": "pramaan-1"})
            except Exception as e:
                print(f"[AuthService] Error loading FIREBASE_ADMIN_CREDENTIALS env: {e}")

        # 2. Try local file path if not initialized yet
        if not firebase_admin._apps and os.path.exists(CREDENTIAL_FILE):
            cred = credentials.Certificate(CREDENTIAL_FILE)
            _firebase_app = firebase_admin.initialize_app(cred, {"projectId": "pramaan-1"})

        # 3. Fallback to default application credentials
        if not firebase_admin._apps:
            _firebase_app = firebase_admin.initialize_app()

    try:
        _db = firestore.client()
    except Exception as e:
        print(f"[AuthService] Warning: Could not initialize Firestore client: {e}")
        _db = None
    return _db


def verify_id_token(id_token: str) -> Dict[str, Any]:
    """Verifies Firebase ID token (from Google Auth or Email/Password)."""
    get_firestore_client()
    if not firebase_admin._apps:
        raise RuntimeError("Firebase Admin SDK is not initialized. Please configure credentials.")
    return auth.verify_id_token(id_token)


def register_user_session(
    id_token: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "Unknown",
    existing_session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Validates the auth token and persists a session record in Firestore."""
    decoded_token = verify_id_token(id_token)
    uid = decoded_token.get("uid")
    email = decoded_token.get("email", "")
    name = decoded_token.get("name", email.split("@")[0] if email else "User")
    auth_provider = decoded_token.get("firebase", {}).get("sign_in_provider", "custom")
    token_exp = decoded_token.get("exp", int(time.time()) + 3600)

    # Cryptographic hash of access/id token (prevents storing raw bearer token in DB while verifying possession)
    token_hash = hashlib.sha256(id_token.encode("utf-8")).hexdigest()

    session_id = existing_session_id or f"sess_{uuid.uuid4().hex[:20]}"
    now = int(time.time())

    session_doc = {
        "session_id": session_id,
        "uid": uid,
        "email": email,
        "name": name,
        "auth_provider": auth_provider,
        "token_hash": token_hash,
        "created_at": now,
        "last_active_at": now,
        "expires_at": token_exp,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "status": "ACTIVE"
    }

    db = get_firestore_client()
    if db is not None:
        try:
            db.collection("user_sessions").document(session_id).set(session_doc)
        except Exception as e:
            print(f"[AuthService] Warning: Failed to write session to Firestore: {e}")

    return {
        "success": True,
        "session_id": session_id,
        "user": {
            "uid": uid,
            "email": email,
            "name": name,
            "auth_provider": auth_provider
        },
        "expires_at": token_exp
    }


def validate_session(session_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Validates if a session exists, is ACTIVE, and is not expired."""
    db = get_firestore_client()
    if db is None:
        return True, {"status": "ACTIVE", "session_id": session_id}

    try:
        doc_ref = db.collection("user_sessions").document(session_id).get()
        if not doc_ref.exists:
            return False, None
        data = doc_ref.to_dict()
        if data.get("status") != "ACTIVE":
            return False, None
        if data.get("expires_at", 0) < int(time.time()):
            return False, None

        # Update last active timestamp asynchronously/periodically
        db.collection("user_sessions").document(session_id).update({
            "last_active_at": int(time.time())
        })
        return True, data
    except Exception as e:
        print(f"[AuthService] Session validation error: {e}")
        return False, None


def revoke_user_session(session_id: str, uid: Optional[str] = None) -> bool:
    """Revokes a session by setting status to REVOKED in Firestore."""
    db = get_firestore_client()
    if db is None:
        return True

    try:
        doc_ref = db.collection("user_sessions").document(session_id)
        doc = doc_ref.get()
        if not doc.exists:
            return False
        data = doc.to_dict()
        if uid and data.get("uid") != uid:
            return False

        doc_ref.update({
            "status": "REVOKED",
            "revoked_at": int(time.time())
        })
        return True
    except Exception as e:
        print(f"[AuthService] Revoke error: {e}")
        return False
