# Egress trust model

This page is what the TLS intercept does and what it does not do. L3 requires `tls_intercept`. That flag is not a statement that the agent is safe.

## What is minted

Each intercepting proxy run creates an ephemeral CA (ECDSA P-256, basic constraints CA, about two hours of validity). The private key is mode `0600` in a temporary directory and is not written to the report, the ledger, or the egress log. Leaf certificates are issued per CONNECT host, with a SAN for that DNS name or IP.

The CA certificate is published to the sandbox only:

- container: read-only mount at `/opt/a3p-ca.pem`, and `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` set inside the container
- bubblewrap: the same path, set with `--setenv`
- process: the child environment copy gets those two variables

The probe process does not set `SSL_CERT_FILE`. A program outside the sandbox that does not trust this CA will fail the handshake instead of being intercepted silently.

## What is decrypted

Allow-list checks happen at three places on an intercepted connection:

1. SNI, when the client sends one, must match the CONNECT host and the allow-list.
2. The HTTP `Host` header must match that same host.
3. If a path prefix list is configured for the host, the path must match a prefix.

Request and response bodies are scanned for configured canaries and for secrets the redactor already knows (`sk-` tokens, bearer tokens, PEM private keys, `A3P-` canaries). The log stores metadata and redacted bodies. A hit is counted. The raw secret is not the log line.

## What is not decrypted

The provider host that holds the API key is pinned. `a3p run` and `a3p scan` pin the host of `base_url`. A pinned CONNECT is a TCP tunnel. The proxy records the method and host, redacts `Authorization` and `Proxy-Authorization`, and does not issue a leaf and does not read the body. Path rules apply to intercepted hosts, not to the pinned tunnel.

`mock://` does not start a proxy. A scripted model therefore has `tls_intercept: false` and cannot reach L3.

## What L3 is claiming

L3 means all of the L2 bar, plus container or bubblewrap, denied network, an intact host marker, no in-process handlers, a model path of `egress-proxy` or an attested `ollama-container`, and an intercepting proxy with a CA. It does not mean a sandbox request was decrypted during the run. It means the proxy was capable of intercepting allow-listed hosts other than the pinned provider.

The tool container is still started with `--network none`. Intercepted egress is for traffic that is sent through the proxy. It is not a claim that a network-none container opens its own TLS. The automatic order is `runsc` when that binary exists, then a container, then nsjail, then bubblewrap. `A3P_ISOLATION` forces one of those even when Docker is installed. A subprocess is used only when `A3P_ISOLATION=process` is set, or when `mcp-scan` is passed `--unsafe-process-sandbox`. That subprocess is not L3. On 14 October 2026 both jails were executed here: network denied, host marker still `safe`, and a demo MCP stdio scan recorded a poisoning finding inside each. nsjail uses a private chroot because `--chroot /` cannot remount a Docker overlay in this VM. nsjail now loads `src/a3p/static/nsjail.kafel` (EPERM for ptrace, mount, kexec, bpf, keyctl, and the other names in that file; this kafel names `umount`, not `umount2`) and leaves NoNewPrivs on. A later attest saw Seccomp 2 and NoNewPrivs 1. runsc uses rootless OCI `runsc --ignore-cgroups --network=none run` with `noNewPrivileges`. The earlier OCI attempt without `--ignore-cgroups` failed with `fork/exec /proc/self/exe: operation not permitted`. With the flag, the worker reported NoNewPrivs 1, network denied, and the host marker intact. Guest Seccomp stays 0 because the filter is gVisor's. `/dev/kvm` is group `docker`. This user was added to that group; the running session still gets EACCES, `sg docker` can open the device, and `runsc --platform=kvm` did not finish within 10 seconds even as root. The attested platform is systrap. `A3P_RUNSC_PLATFORM=kvm` selects KVM for a session that can open the device. The commands are in `command_for`. Details are in [METHOD.md](METHOD.md).

Ollama is planned with no published host port. The access path is a unix socket and a per-run bearer token. The token is a mode-0600 file in the socket directory. `docker inspect` shows the directory and does not include the token. Anyone who can read that file and the socket can connect. Root on the host can read the file.

## MCP sandbox and keyless signatures

A live MCP scan uses the same jail as a tool handler: no IP network, read-only root, and a host marker the server is not supposed to rewrite. The operator names the server with `--command`. HTTP/SSE is not a published TCP port. A server that listens on a unix socket is mounted into the sandbox. A server that only binds `127.0.0.1` inside the sandbox is reached by `a3p.mcp_bridge`, which copies bytes from that unix socket to loopback and refuses any other target address. The container network stays closed. The process sandbox is refused unless `--unsafe-process-sandbox` is set. Its network and host files stay open. That is not L3.

New badges put `sigstore_sha256` inside the Ed25519 payload. The value is the hash of the Sigstore bundle, or the hash of the marker `absent` when Fulcio was not contacted. The bundle bytes are attached beside the signature. Replacing the bundle breaks the Ed25519 check. `a3p verify-badge --identity --issuer` checks the bundle against the badge body that excludes that hash (the bytes Fulcio signed), including the certificate identity and the Rekor inclusion proof. Fulcio is contacted only when an ambient OIDC token exists. This workspace had none. GitHub Actions provides one when the job sets `id-token: write`. Until that job has run on GitHub, there is no Fulcio certificate to show. Older badges without `sigstore_sha256` still verify offline, and their Ed25519 signature does not bind a bundle. Neither signature is a certification.

## Operator duties

- Treat the per-run CA as a secret for the length of the run. It can mint leaves for any host the sandbox will trust.
- Do not copy the CA into the host trust store.
- Do not put a host on the allow-list if you are not willing to decrypt it.
- Keep the provider host pinned. Unpinning it would put the API key's TLS session inside the intercept.
- A passing L3 sample is still one sample.
