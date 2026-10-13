// Context is constructed ONLY by trusted Rust code after signature, scope,
// expiry, resource and approval checks. Agent input cannot set these fields.
permit(principal, action, resource)
when { context.task_valid && context.in_scope && context.approved };

forbid(principal, action, resource)
when { context.sensitive };
