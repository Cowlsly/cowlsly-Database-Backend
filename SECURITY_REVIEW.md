# Security review — 2026-10-08

Scope: post-merge validation of the Hono 4.8.5 → 4.13.7 upgrade (#7, `00e9dc4`) and the Worker's security-sensitive routes in `src/index.js`.

## Upgrade result

The regression suite (`npm test`, `test/app.test.mjs`) passed on both Hono 4.13.7 and 4.8.5 in CI (run 3, PR #8), so the upgrade changed no tested routing or middleware behaviour. That includes the two routes registered without a leading slash, which are reachable at `/<name>` on both versions. `wrangler deploy --dry-run` bundles the Worker without errors. No deployment was made.

## Fixed

| Finding | Severity | Fix |
|---|---|---|
| `/getUser` wrong-password response appended the stored bcrypt hash to the error text | High | Error text is `Invalid password` only |
| `/getUser` successful login returned the stored hash as `data.Password` | High | Field removed; other fields unchanged |

Both are covered by `/getUser never returns the stored password hash` in `test/app.test.mjs`.

## Open — needs an owner decision (pre-existing, not caused by the upgrade)

1. **Effectively no authentication.** `/get-sign` gives a valid sign to any caller, and the sign is the only check on every other route.
2. **Account takeover.** `/updateMemberPass`, `/updateMemberEmail`, `/updateMemberRole` and `/deleteMember` need only a name and email: no current password or session.
3. **CORS allows any origin** (`cors()` defaults).
4. **User enumeration.** `/getUser` returns "User not found" (404) separately from "Invalid password" (401).
5. **`/addReport` maps dataset keys by position.** A body containing only `Three` writes `DataSetOne`.
6. **Double-quoted string literals in SQL** (`Role = "Scouter"`) depend on SQLite's legacy fallback.

Items 1–2 need a real auth model (for example, a session issued only after `/getUser` succeeds, required on write routes, plus the current password for credential changes). That changes the client contract, so the client app must change at the same time.
