"""
In-memory store for centralized OAuth/OIDC sessions, pending browser logins,
single-use authorization codes, and dynamically registered MCP OAuth 2.1 clients.
"""

import base64
import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

ALLOWED_CUSTOM_SCHEMES = {"cursor", "vscode", "vscode-insiders", "claude", "windsurf"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a (code_verifier, code_challenge_S256) pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def verify_pkce_challenge(
    code_verifier: str, code_challenge: Optional[str], method: str = "S256"
) -> bool:
    """Verify RFC 7636 PKCE code_verifier against code_challenge."""
    if not code_challenge or not code_verifier:
        return False
    normalized_method = (method or "S256").upper()
    try:
        if normalized_method == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            return hmac.compare_digest(computed, code_challenge)
        if normalized_method == "PLAIN":
            return hmac.compare_digest(code_verifier, code_challenge)
    except (UnicodeEncodeError, TypeError):
        return False
    return False


def validate_client_redirect_uri(uri: str) -> str:
    """
    Validate a redirect URI for Dynamic Client Registration (RFC 7591) and /oauth/authorize.

    Allows loopback HTTP/HTTPS URIs (127.0.0.1, localhost, ::1) and approved IDE custom schemes.
    Raises ValueError on untrusted external redirect URIs to prevent open-redirect attacks.
    """
    if not uri or not isinstance(uri, str):
        raise ValueError("Invalid redirect_uri: must be a non-empty string")
    parsed = urlsplit(uri.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme in ALLOWED_CUSTOM_SCHEMES:
        return uri.strip()
    if scheme in ("http", "https") and (parsed.hostname or "").lower() in LOOPBACK_HOSTS:
        return uri.strip()
    raise ValueError(
        f"Invalid redirect_uri '{uri}': only loopback addresses (127.0.0.1, localhost, ::1) "
        f"or IDE schemes ({sorted(ALLOWED_CUSTOM_SCHEMES)}) are permitted."
    )


@dataclass
class OAuthSession:
    """Represents an authenticated user's session mapped to an mcp_ bearer token."""

    mcp_token: str = field(repr=False)
    downstream_refresh_token: str = field(repr=False)
    access_token: str = field(repr=False)
    refresh_token: Optional[str] = field(repr=False)
    token_type: str
    expires_at: float
    session_expires_at: float
    user_hint: Optional[str] = None
    refresh_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def is_access_token_expiring(self, buffer_seconds: int = 60) -> bool:
        return time.time() + buffer_seconds >= self.expires_at


@dataclass
class PendingAuthRequest:
    """State for an in-flight browser login started via /oauth/authorize or /auth/login."""

    upstream_state: str
    upstream_code_verifier: str = field(repr=False)
    upstream_code_challenge: str
    flow_type: str  # "mcp_oauth" or "portal"
    created_at: float
    expires_at: float
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    downstream_state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: str = "S256"


@dataclass
class IssuedAuthCode:
    """Short-lived single-use authorization code issued to an MCP OAuth client."""

    code: str = field(repr=False)
    mcp_token: str = field(repr=False)
    client_id: Optional[str]
    redirect_uri: Optional[str]
    code_challenge: Optional[str]
    code_challenge_method: str
    expires_at: float


@dataclass
class RegisteredClient:
    """Dynamically registered MCP OAuth 2.1 client."""

    client_id: str
    client_name: str
    redirect_uris: List[str]
    created_at: float


class OAuthSessionStore:
    """Thread-safe in-memory storage for OAuth sessions, pending states, codes, and clients."""

    def __init__(
        self,
        session_ttl_seconds: int = 86400,
        pending_ttl_seconds: int = 600,
        auth_code_ttl_seconds: int = 60,
        max_sessions: int = 2048,
        max_pending: int = 1000,
        max_clients: int = 2048,
    ):
        self._session_ttl = session_ttl_seconds
        self._pending_ttl = pending_ttl_seconds
        self._code_ttl = auth_code_ttl_seconds
        self._max_sessions = max_sessions
        self._max_pending = max_pending
        self._max_clients = max_clients
        self._lock = threading.Lock()
        self._sessions: Dict[str, OAuthSession] = {}
        self._refresh_index: Dict[str, str] = {}
        self._pending: Dict[str, PendingAuthRequest] = {}
        self._codes: Dict[str, IssuedAuthCode] = {}
        self._clients: Dict[str, RegisteredClient] = {}

    def _cleanup_locked(self, now: float) -> None:
        expired_sessions = [
            tok for tok, sess in self._sessions.items() if sess.session_expires_at <= now
        ]
        for tok in expired_sessions:
            sess = self._sessions.pop(tok, None)
            if sess:
                self._refresh_index.pop(sess.downstream_refresh_token, None)
        while len(self._sessions) >= self._max_sessions:
            oldest_tok = next(iter(self._sessions))
            sess = self._sessions.pop(oldest_tok, None)
            if sess:
                self._refresh_index.pop(sess.downstream_refresh_token, None)

        expired_pending = [st for st, p in self._pending.items() if p.expires_at <= now]
        for st in expired_pending:
            self._pending.pop(st, None)
        while len(self._pending) >= self._max_pending:
            oldest_st = next(iter(self._pending))
            self._pending.pop(oldest_st, None)

        expired_codes = [c for c, obj in self._codes.items() if obj.expires_at <= now]
        for c in expired_codes:
            self._codes.pop(c, None)

        while len(self._clients) >= self._max_clients:
            oldest_client = next(iter(self._clients))
            self._clients.pop(oldest_client, None)

    def create_session(
        self,
        *,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_type: str = "Bearer",
        expires_in: int = 1800,
        user_hint: Optional[str] = None,
        session_ttl_seconds: Optional[int] = None,
    ) -> OAuthSession:
        now = time.time()
        ttl = session_ttl_seconds or self._session_ttl
        mcp_token = f"mcp_{secrets.token_urlsafe(32)}"
        downstream_refresh = f"mcpr_{secrets.token_urlsafe(32)}"
        session = OAuthSession(
            mcp_token=mcp_token,
            downstream_refresh_token=downstream_refresh,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type or "Bearer",
            expires_at=now + max(int(expires_in or 1800), 30),
            session_expires_at=now + ttl,
            user_hint=user_hint,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._sessions[mcp_token] = session
            self._refresh_index[downstream_refresh] = mcp_token
        return session

    def get_session(self, mcp_token: str) -> Optional[OAuthSession]:
        if not mcp_token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(mcp_token)
            if not session:
                return None
            if session.session_expires_at <= now:
                self._sessions.pop(mcp_token, None)
                self._refresh_index.pop(session.downstream_refresh_token, None)
                return None
            return session

    def get_session_by_downstream_refresh_token(
        self, downstream_refresh_token: str
    ) -> Optional[OAuthSession]:
        if not downstream_refresh_token:
            return None
        with self._lock:
            mcp_token = self._refresh_index.get(downstream_refresh_token)
        if not mcp_token:
            return None
        return self.get_session(mcp_token)

    def update_session_tokens(
        self,
        mcp_token: str,
        *,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_type: Optional[str] = None,
        expires_in: int = 1800,
        user_hint: Optional[str] = None,
    ) -> Optional[OAuthSession]:
        now = time.time()
        with self._lock:
            session = self._sessions.get(mcp_token)
            if not session or session.session_expires_at <= now:
                return None
            session.access_token = access_token
            if refresh_token:
                session.refresh_token = refresh_token
            if token_type:
                session.token_type = token_type
            session.expires_at = now + max(int(expires_in or 1800), 30)
            session.session_expires_at = max(session.session_expires_at, now + self._session_ttl)
            if user_hint:
                session.user_hint = user_hint
            return session

    def revoke_session(self, mcp_token: str) -> bool:
        if not mcp_token:
            return False
        with self._lock:
            session = self._sessions.pop(mcp_token, None)
            if session:
                self._refresh_index.pop(session.downstream_refresh_token, None)
                return True
            return False

    def create_pending_auth(
        self,
        *,
        flow_type: str,
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        downstream_state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> PendingAuthRequest:
        now = time.time()
        upstream_state = secrets.token_urlsafe(24)
        verifier, challenge = generate_pkce_pair()
        pending = PendingAuthRequest(
            upstream_state=upstream_state,
            upstream_code_verifier=verifier,
            upstream_code_challenge=challenge,
            flow_type=flow_type,
            created_at=now,
            expires_at=now + self._pending_ttl,
            client_id=client_id,
            redirect_uri=redirect_uri,
            downstream_state=downstream_state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "S256",
        )
        with self._lock:
            self._cleanup_locked(now)
            self._pending[upstream_state] = pending
        return pending

    def pop_pending_auth(self, upstream_state: str) -> Optional[PendingAuthRequest]:
        if not upstream_state:
            return None
        now = time.time()
        with self._lock:
            pending = self._pending.pop(upstream_state, None)
            if not pending or pending.expires_at <= now:
                return None
            return pending

    def issue_auth_code(
        self,
        *,
        mcp_token: str,
        client_id: Optional[str],
        redirect_uri: Optional[str],
        code_challenge: Optional[str],
        code_challenge_method: str = "S256",
    ) -> IssuedAuthCode:
        now = time.time()
        code = f"mcpc_{secrets.token_urlsafe(24)}"
        issued = IssuedAuthCode(
            code=code,
            mcp_token=mcp_token,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "S256",
            expires_at=now + self._code_ttl,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._codes[code] = issued
        return issued

    def consume_auth_code(self, code: str) -> Optional[IssuedAuthCode]:
        if not code:
            return None
        now = time.time()
        with self._lock:
            issued = self._codes.pop(code, None)
            if not issued or issued.expires_at <= now:
                return None
            return issued

    def register_client(self, *, client_name: str, redirect_uris: List[str]) -> RegisteredClient:
        if not redirect_uris or not isinstance(redirect_uris, list):
            raise ValueError("redirect_uris must be a non-empty list")
        validated_uris = [validate_client_redirect_uri(u) for u in redirect_uris]
        now = time.time()
        client_id = f"mcp_client_{secrets.token_urlsafe(16)}"
        client = RegisteredClient(
            client_id=client_id,
            client_name=(client_name or "MCP Client").strip(),
            redirect_uris=validated_uris,
            created_at=now,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._clients[client_id] = client
        return client

    def get_client(self, client_id: str) -> Optional[RegisteredClient]:
        if not client_id:
            return None
        with self._lock:
            return self._clients.get(client_id)
