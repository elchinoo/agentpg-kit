"""Authentication and authorization blocks.

* `AppAuth`: what an app declares (its audience, its permissions, which roles and scopes grant which).
* `Principal`: who is calling and what they may do.
* `LocalAuth`: standalone mode (admin password, sessions, local tokens, static key).
* `TokenVerifier`, `RelyingParty`: federated mode (verify the ecosystem identity provider's tokens; log users in with OIDC).
* `Authenticator`: one `require()` that accepts either.
"""
from .authenticator import Authenticator
from .env import Federation, from_env
from .local import LocalAuth
from .oidc import TokenError, TokenSource, TokenVerifier
from .principal import AppAuth, Principal
from .rp import LoginStart, RelyingParty, clear_binding

__all__ = ["AppAuth", "Authenticator", "Federation", "LocalAuth", "LoginStart", "from_env", "Principal", "RelyingParty", "clear_binding", "TokenError", "TokenSource", "TokenVerifier"]
