# CLAUDE.md

Signaling server for Secure Call, a secure 1-to-1 video calling web app. Python 3.14 + Django +
Channels (Daphne) + Pydantic, managed with uv. The web client lives in
https://github.com/The-Secure-Video-Call/secure-call; its **PLAN.md** holds the architecture,
security design (section 3), signaling protocol (section 6) and milestones. Read the relevant
sections before starting any task.

## Security ground rules (never break these)

- The server treats every `payload` as opaque. It never decrypts, parses, stores or logs it.
- Never log message contents, room IDs, or IP addresses. Log level defaults to WARNING.
- Validate every incoming message with the Pydantic models in `signaling/protocol.py` before
  acting on it. Reject unknown fields. Close the connection on malformed input.
- Keep the WebSocket Origin check (`OriginValidator` in `config/asgi.py`), the message size limit,
  rate limits and the 2-person room limit. Never weaken them, or the security headers and HTTPS
  settings in `config/settings.py`, to make something work. Explain in the PR instead.
- PostgreSQL is connected (when `POSTGRES_HOST` is set) for future user accounts only. Never
  store call data in it: no room IDs, call times, IP addresses or message contents. Adding
  tables, sessions or accounts needs a PLAN.md change first. The database is never exposed
  to the internet.
- Never commit secrets. Everything environment-specific comes from environment variables, and the
  defaults must stay safe for production (DEBUG off, no allowed origins).
- TURN credentials are short-lived HMAC credentials only (PLAN.md 3.5); no static passwords.

## Structure (keep it flat and simple)

- `config/`: settings, ASGI and URL routing only.
- `signaling/`: one module per job, named for that job: `protocol.py` (message models),
  `consumers.py` (WebSocket handling), `rooms.py` (room state), `views.py` (HTTP endpoints).
  A new job gets a new module here, e.g. `turn_credentials.py`, `rate_limits.py`.
- `tests/`: one `test_<module>.py` per module it tests.
- No extra layers or catch-all modules (`services/`, `managers/`, `helpers/`, `utils.py`) and no
  folders nested deeper than `signaling/` unless a PR explains why they are needed.

## Code conventions

- Type hints everywhere; `uv run mypy .` (strict) must pass.
- No relative imports: always import from the package root, e.g. `from signaling.protocol import Envelope`,
  never `from .protocol import Envelope`. Ruff enforces this (TID252).
- Names say exactly what the value holds, even if that makes them long: `members_by_room_id`,
  `max_message_bytes`, `peer_channel_name`, not `d`, `tmp`, `data`, `info` or `obj`. Single letters
  only for short loop counters. Functions are named for what they do (`relay_signal_to_peer`).
- `uv run ruff check` and `uv run ruff format --check` must pass (security rules included).
- Every change to protocol, room or consumer logic needs tests, including at least one negative
  test (tampered, replayed, oversized or malformed input is rejected).
- Protocol changes: edit `signaling/protocol.py`, run `uv run python -m signaling.export_schema`,
  and add valid/invalid examples to `protocol/fixtures/`. The web client depends on these files.
- Add dependencies with `uv add` only when clearly needed, and say why in the PR.

## The other repo

Every Claude run (tasks and reviews) has a read-only copy of secure-call's latest `main` at
`.reference/secure-call/`. Read it to see how the web app really uses the server (`apps/web/src/signaling/`,
`apps/web/src/rtc/`, `packages/protocol/`) before changing what the server sends or accepts.

- Never edit or commit anything under `.reference/` (git ignores it anyway).
- If the work needs a change in secure-call, don't work around it here: say in your reply
  what has to change there and why, so it can become an issue in that repo.

### When work in the two repos depends on each other

The two Claudes can't talk to each other or see each other's unmerged branches, only `main`.

1. **The message contract comes first.** The backend's `signaling/protocol.py` (exported to
   `protocol/`) is the agreed interface. Code against the contract, never against code that
   isn't merged yet. A contract change is made in the backend first; the web app follows after
   it is merged (`pnpm protocol:sync`).
2. **Check before you start.** If the issue says "Depends on" another issue, look in
   `.reference/secure-call/` (or this repo) for what it needs. If it isn't on `main` yet,
   don't build a stand-in or guess: reply **"Blocked by <repo>#<issue>"**, list exactly what
   you need from it, and stop without pushing.
3. **Never change the other side's behaviour by assumption.** If you find the contract or the
   other repo's code doesn't support what your issue needs, say what has to change and why;
   the change becomes its own issue there, and your issue waits for it.
4. **Keep each side working on its own.** Merge order follows the dependencies (contract,
   then server, then client), and every PR must pass its own CI without the other's
   unmerged work.

## Working on issues

- One milestone checklist item per pull request. Reference the issue (`Closes #<number>`).
- Run the checks before pushing: `uv run ruff check && uv run ruff format --check && uv run mypy . && uv run pytest`.
- Explain any security-relevant decision in the PR description.
- For changes to the consumer, protocol, settings or ASGI routing, ask the `security-reviewer`
  subagent to review before finishing.
