# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's "Report a vulnerability"
button (Security tab → Advisories) rather than opening a public issue. If
that isn't available, open an issue with minimal detail asking for a private
contact channel.

## Scope

This library persists only an HMAC digest of each rate-limited subject
(`ip:...`/`user:...`), never the raw IP address or user id, and holds no
credentials itself beyond the one secret you configure it with.

Things worth reporting:
- A way to bypass a `FAIL_CLOSED` policy without a genuine backend outage.
- A way to make `subject_hmac` collide across two different real subjects.
- A way to poison another subject's bucket (cross-subject increment) via the
  batched `hit_many` path.
- Any scenario where a `FAIL_OPEN` policy's degraded response leaks more
  than the fact that the backend is unavailable.

## Not in scope

- Denial of service via sustained legitimate-looking traffic — that's the
  problem this library helps *you* solve, not a vulnerability in it.
- Misconfiguration (e.g. reusing `subject_secret` from another purpose,
  setting every policy to `FAIL_OPEN`) — see README's Security section for
  the configuration choices that affect your own security posture.

## Supported versions

This is a single-branch project (`main`); only the latest commit is
supported.
