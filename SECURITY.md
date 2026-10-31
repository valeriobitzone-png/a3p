# Security

A3P is a sample-based assessment tool. A passing report is not a statement that a model, agent, or deployment is safe. Method v1.0 levels describe how a sample was run. They are not a security guarantee.

## Report a vulnerability

Use [docs/DISCLOSURE.md](docs/DISCLOSURE.md). This project is not published, so there is no public issue tracker and no bounty. Send the report to the maintainer of the checkout you are using. Do not start with a public exploit.

## What to include

- The package version and the method version (`v1.0` unless a newer method document shipped).
- The isolation levels the report recorded for tools, model, and probe.
- A reproduction that does not include live API keys, customer data, or the signing private key.
- The effect you observed, and what you expected the sandbox or the badge check to do.

## What this file does not promise

- Coordinated disclosure with a vendor you probed. Their process is theirs.
- That `process` isolation closes network or host files. It does not.
- That the egress proxy sees or blocks payloads inside TLS. It allow-lists the destination host and redacts Authorization in its own log.
- That an Ollama container published on `127.0.0.1` is hidden from other local processes.
- A patch timeline. The maintainer of a given checkout decides what to change.

Signing keys in a report directory are public keys only. If a private key was written into a report, treat it as compromised and run `a3p keys rotate`.
