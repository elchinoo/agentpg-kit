# Security policy

Report vulnerabilities privately (GitHub: Security tab, "Report a vulnerability"). This library holds the security-critical
code of every app that uses it (password hashing, the vault, the SSRF guard, token verification, the CSRF/CSP middleware), so
a fix here is a fix everywhere; apps pick it up by moving to the new release tag.

Design points: tokens are verified with an algorithm allow-list and mandatory issuer/audience/expiry; sessions, tokens and
keys are stored only as hashes; stored secrets are encrypted under a key that the database alone does not reveal; outbound URLs
are checked on every call and redirects are never followed; browser writes need a custom header.
Limits: rate limiting is per process; the SSRF guard resolves the host name once for the check and once for the request.
