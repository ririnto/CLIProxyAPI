# Executor Lifecycle

- Bind compaction to the selected executor, auth ID, and normalized endpoint.
- Use only the selected static credential or its persisted verified-account OAuth root.
- Static credential changes invalidate the previous compaction binding.
- Preserve OAuth roots across verified same-account refresh, including CLIProxyAPIHome.
- Give each new login or changed account a distinct root.
- Missing OAuth roots fail compaction but leave ordinary OAuth requests available.
- Restore missing roots only through authenticated refresh or login.
- Keep native Codex WebSocket steering and queued creates in the built-in executor.
