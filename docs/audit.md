# Audit model

Remote execution and remote file access are security-sensitive, so gateway
actions must be auditable independently of conversational history.

The prototype uses an append-only JSONL audit sink. The v1 control plane records
metadata for:

- device status checks;
- command execution;
- file reads;
- file writes.

Each event contains:

- UTC timestamp;
- authenticated platform subject;
- device ID;
- action;
- success/failure;
- duration;
- remote exit code when applicable.

Command text, file paths/content, stdout and stderr require a deliberate
retention/privacy decision before being logged because they can contain
credentials, personal data or other sensitive material. They are therefore not
part of the default audit event.

The audit path is private runtime state and must not be committed to the public
repository. The reference default is:

```text
/var/lib/ai-lab-gateway/audit.jsonl
```

The JSONL implementation is a prototype seam, not a permanent storage
decision. A database or external log sink can replace it without changing the
authorization model.

## Acceptance check

After exercising the live MCP tools, inspect recent audit records as the service
operator and verify that the expected actions are present without leaking
command/file contents.

Do not use the audit log as a substitute for OAuth or device authorization. It
is evidence after an authorization decision, not an access-control mechanism.

## Remaining operational decision

Retention, rotation, backup and deletion periods are intentionally not fixed
yet. Define them before treating the JSONL sink as a long-term production audit
system.
