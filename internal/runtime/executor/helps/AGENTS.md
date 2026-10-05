# Executor Helpers

- Keep capsule helpers limited to authenticated sealing and opening.
- Require callers to provide executor ID, auth ID, normalized endpoint, and key material.
- Reject missing scope, missing key material, and authentication failures.
