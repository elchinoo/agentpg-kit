"""Turn on federation from environment variables, the same way in every app.

    <PREFIX>_OIDC_ISSUER          the ecosystem identity provider's URL (federation is off when unset)
    <PREFIX>_OIDC_CLIENT_ID       this app's client id at the provider (default: the app name)
    <PREFIX>_OIDC_CLIENT_SECRET   its secret (or <PREFIX>_OIDC_CLIENT_SECRET_FILE), read when a login needs it (first token exchange),
                                  never at import: with sealed boot it does not exist until unseal. Empty (and sealing off or open)
                                  means a public client (PKCE only)
    <PREFIX>_OIDC_PUBLIC_CLIENT   true declares a public client on purpose; it is the only way to stay public while sealed and not yet
                                  unsealed (otherwise token exchange fails closed until the secret is readable)
    <PREFIX>_LOCAL_LOGIN          keep the local admin password as a break-glass login (default true)
"""
import os
from dataclasses import dataclass

from ..config import env_bool, read_secret
from .oidc import TokenVerifier, jwks_ttl_from_env
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
    # The client type comes from configuration, never from whether the secret happens to be readable right now.
    secret = None if env_bool(f"{prefix}_OIDC_PUBLIC_CLIENT", False) else (lambda: read_secret(f"{prefix}_OIDC_CLIENT_SECRET"))
    return Federation(issuer.rstrip("/"), client_id, TokenVerifier(issuer, client_id, ttl=jwks_ttl_from_env(prefix)), RelyingParty(issuer, client_id, secret),
                      local_login)
