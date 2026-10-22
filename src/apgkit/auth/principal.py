from dataclasses import dataclass, field

WILDCARD = "*"


@dataclass(frozen=True)
class AppAuth:
    """What an application declares about its own authorization.

    `role_permissions` maps a role (granted to people by the identity provider, namespaced `<app>:<role>` in tokens) to the
    permissions it carries. `scope_permissions` maps an OAuth scope (what a service or local token was granted) to
    permissions. `*` means everything. The app's code only ever asks `principal.can("requests:decide")`.
    """
    name: str                                        # short app name, also the role namespace: roles look like "trustdesk:approver"
    audience: str                                    # the identity provider's client id for this app
    role_permissions: dict[str, frozenset[str]] = field(default_factory=dict)
    scope_permissions: dict[str, frozenset[str]] = field(default_factory=dict)

    def role_name(self, role: str) -> str | None:
        """`trustdesk:approver` -> `approver` for this app; roles of other apps are not ours (None); a bare role is ours."""
        ns, sep, rest = role.partition(":")
        if not sep:
            return role
        return rest if ns == self.name else None

    def permissions_for(self, roles=(), scopes=()) -> frozenset[str]:
        out: set[str] = set()
        for r in roles:
            name = self.role_name(r)
            if name is not None:
                out |= self.role_permissions.get(name, frozenset())
        for s in scopes:
            out |= self.scope_permissions.get(s, frozenset())
        return frozenset(out)


@dataclass(frozen=True)
class Principal:
    kind: str                          # session | token | static | service | user | merchant | anonymous
    subject: str                       # stable identifier: user id, client id, key id, "local-admin"
    permissions: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    name: str = ""
    email: str = ""
    source: str = "local"              # local | oidc
    ident: int | None = None
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    def can(self, permission: str) -> bool:
        return WILDCARD in self.permissions or permission in self.permissions

    @property
    def actor(self) -> str:
        """A short label for audit trails."""
        return (self.name or self.subject)[:60]
