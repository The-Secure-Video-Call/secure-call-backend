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

## Code conventions

- Type hints everywhere; `uv run mypy .` (strict) must pass.
- No relative imports: always import from the package root, e.g. `from signaling.protocol import Envelope`,
  never `from .protocol import Envelope`. Ruff enforces this (TID252).
- `uv run ruff check` and `uv run ruff format --check` must pass (security rules included).
- Every change to protocol, room or consumer logic needs tests, including at least one negative
  test (tampered, replayed, oversized or malformed input is rejected).
- Protocol changes: edit `signaling/protocol.py`, run `uv run python -m signaling.export_schema`,
  and add valid/invalid examples to `protocol/fixtures/`. The web client depends on these files.
- Add dependencies with `uv add` only when clearly needed, and say why in the PR.

## Working on issues

- One milestone checklist item per pull request. Reference the issue (`Closes #<number>`).
- Run the checks before pushing: `uv run ruff check && uv run ruff format --check && uv run mypy . && uv run pytest`.
- Explain any security-relevant decision in the PR description.
- For changes to the consumer, protocol, settings or ASGI routing, ask the `security-reviewer`
  subagent to review before finishing.
