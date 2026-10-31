# World verifiers

A verifier is a read the probe owns. It is the difference between a tool receipt and a fact (A3-EP CF-001). These adapters do not call the agent. They answer a query about a system the operator pointed them at.

They are read-only by construction:

- SQL allows one `SELECT` or `WITH` statement and rejects write keywords.
- The filesystem adapter reads a file under a root and refuses `..`.
- Git uses `rev-parse`, `status --porcelain`, and `hash-object`.
- GitHub is a GET of one commit.
- Mail reads an mbox, a directory of `.eml` files, an IMAP INBOX, or messages a local SMTP sink accepted.
- REST allows GET and HEAD only.
- Slack reads `conversations.history`. Jira reads one issue. S3-compatible storage is GET of an object or a bucket list. Signing is a header or a pre-signed URL you pass in. This is not the AWS SDK.

SQLite is built in. Postgres uses the optional `world` extra (`psycopg`). If the driver is missing, `connect_postgres` says so and you pass an open connection instead. A test in this repo started Postgres 16 in Docker and ran a SELECT. The same run started Mailpit and read the message through its HTTP API. MinIO's container image could not be pulled here; the S3 test used the official linux-amd64 binary `RELEASE.2025-09-07T16-13-09Z`. S3 checks stay unsigned GET. boto3 is not a dependency. Docker tests skip when no daemon answers.

None of these reads is a certification. A matching row, file, or message is evidence about that query only.

## Write a verifier

```python
from a3p.world import Observation, run_verifier

class LedgerBalance:
    name = "ledger-balance"

    def __init__(self, balance: int) -> None:
        self.balance = balance

    def read(self, query: dict) -> Observation:
        expected = int(query.get("expected") or 0)
        ok = self.balance == expected
        return Observation(self.name, ok, f"balance {self.balance}", {"balance": self.balance})

obs = run_verifier(LedgerBalance(0), {"expected": 0})
assert obs.ok
```

`run_verifier` checks that `read` returned an `Observation`. Put the check next to the scenario that claimed the world changed. Do not copy the agent's tool result into `data` and call that a fact.

## What is not in this package

- A hosted integration for every SaaS product.
- A Postgres server inside the package. Tests use SQLite, and Docker when a daemon answers.
- Mutating verifiers. If a check needs to send mail, that sender is not a verifier. The SMTP sink only receives, and the probe reads what arrived.
