"""Turn on federation from environment variables, the same way in every app.

    <PREFIX>_OIDC_ISSUER          the ecosystem identity provider's URL (federation is off when unset)
    <PREFIX>_OIDC_CLIENT_ID       this app's client id at the provider (default: the app name)
    <PREFIX>_OIDC_CLIENT_SECRET   its secret (or <PREFIX>_OIDC_CLIENT_SECRET_FILE); empty means a public client (PKCE only)
    <PREFIX>_LOCAL_LOGIN          keep the local admin password as a break-glass login (default true)
"""
import os
from dataclasses import dataclass

from ..config import env_bool, read_secret
from .oidc import TokenVerifier
from .rp import RelyingParty


@dataclass(frozen=True)
class Federation:
    issuer: str
    client_id: str
    verifier: TokenVerifier | None
    rp: RelyingParty | None
    local_login: bool

    @property
    def enabled(self) -> bool:
        return self.verifier is not None


def from_env(prefix: str, default_client_id: str) -> Federation:
    prefix = prefix.upper()
    issuer = os.environ.get(f"{prefix}_OIDC_ISSUER", "").strip()
    client_id = os.environ.get(f"{prefix}_OIDC_CLIENT_ID", default_client_id)
    local_login = env_bool(f"{prefix}_LOCAL_LOGIN", True)
    if not issuer:
        return Federation("", client_id, None, None, True)
    secret = lambda: read_secret(f"{prefix}_OIDC_CLIENT_SECRET")  # noqa: E731
    return Federation(issuer.rstrip("/"), client_id, TokenVerifier(issuer, client_id), RelyingParty(issuer, client_id, secret if secret() else None),
                      local_login)
