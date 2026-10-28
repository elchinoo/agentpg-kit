"""This app's instances of the kit blocks and its authorization model."""
from apgkit import metrics as metrics_mod
from apgkit.auth import AppAuth, Authenticator, LocalAuth, from_env
from apgkit.config import env_bool
from apgkit.db import Database
from apgkit.vault import Vault

from . import __version__

APP, COOKIE, CSRF_HEADER, TOKEN_PREFIX = "notes", "nt_session", "x-notes-csrf", "nt_"

ALL = frozenset({"*"})
ROLE_PERMISSIONS = {                                   # roles people get from the identity provider ("notes:editor")
    "admin": ALL,
    "editor": frozenset({"notes:read", "notes:write"}),
    "viewer": frozenset({"notes:read"}),
}
SCOPE_PERMISSIONS = {                                  # scopes of local API tokens and of service clients
    "read": frozenset({"notes:read"}),
    "full": ALL,
    "notes.read": frozenset({"notes:read"}),
}

db = Database(pool_max=5)
metrics = metrics_mod.Metrics(APP, __version__)
vault = Vault("NOTES")                                 # NOTES_ENCRYPTION_KEY (or /etc/notes/encryption_key) unlocks it at boot
fed = from_env("NOTES", APP)                           # NOTES_OIDC_* turns single sign-on on; unset = standalone
app_auth = AppAuth(APP, fed.client_id, ROLE_PERMISSIONS, SCOPE_PERMISSIONS)
local = LocalAuth(app_auth, env_prefix="NOTES", token_prefix=TOKEN_PREFIX, token_scopes={"read", "full"}, vault=vault,
                  on_reset=lambda conn: conn.execute("DELETE FROM note WHERE private"))   # a reset vault cannot read private notes
auth = Authenticator(app_auth, local, db, cookie_name=COOKIE, verifier=fed.verifier,
                     allow_anonymous=lambda: env_bool("NOTES_ALLOW_ANONYMOUS"))


def _probe() -> dict[str, float]:
    with db.connect(retries=1) as conn:
        conn.execute("SELECT 1")
    return {"db_up": 1}


metrics.add_db_collector(_probe)                       # db_up is 0 when the database cannot be reached
