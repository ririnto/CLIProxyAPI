# Codex Auth Storage

- Generate a fresh compaction root after successful OAuth login.
- Retain roots across token refresh only after verifying the same account.
- Never reuse a root after account identity changes.
- Persist roots in typed credential storage, not runtime metadata or public auth output.
