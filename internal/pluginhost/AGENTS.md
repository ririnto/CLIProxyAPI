# Plugin Host

- Keep host-side plugin loading, RPC adapters, and callback lifecycles in this package.
- Fail before external work when a required host callback is unavailable.
- Scope callbacks to the owning plugin and request context.
- Reject callback operations from a closed request or a different plugin.
- Propagate request cancellation to outbound HTTP and close response bodies.
- Honor required direct-connection, redirect, and response-size settings.
- Redact provider response bodies and caller payloads before returning errors or writing logs.
