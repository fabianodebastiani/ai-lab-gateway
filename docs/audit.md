# Audit model

Remote execution is security-sensitive, so gateway actions should be auditable
independently of conversational history.

The prototype includes an append-only JSONL audit sink. The initial event
metadata is intentionally small:

- UTC timestamp;
- authenticated platform subject;
- device ID;
- action;
- success/failure;
- duration;
- remote exit code when applicable.

Command text, stdout and stderr require a deliberate retention policy before
being logged because they can contain credentials, personal data or other
sensitive material. They are therefore not part of the default audit event.

The JSONL implementation is a prototype seam, not a permanent storage
decision. A database or external log sink can replace it without changing the
authorization model.
