# ascend-tunnel

The Straiker Ascend tunnel agent. Run it on any machine inside your network that can reach the AI
app you want to red-team, and Ascend reaches that app through one outbound HTTPS connection - no
inbound ports, no VPN, no DNS or cloud changes.

```
Straiker Ascend ──► Straiker relay ◄──── outbound HTTPS (WebSocket) ──── ascend-tunnel ──► your app
                                                                         (your network)
        └──────────────────── TLS end to end, Ascend to your app ────────────────────┘
```

- **Outbound only.** The agent dials out to Straiker's relay on 443, through your proxy if you have
  one. Nothing connects in.
- **Reaches only what you list.** Each `--allow host[:port]` is one fixed forward; the agent dials
  nothing else, whatever it is asked.
- **Sees only ciphertext.** TLS runs end to end from Ascend to your app; the agent splices bytes.
- **Your key, on your machine.** The agent generates its key on first start and never sends the
  private half anywhere. You authorize it by pasting the public half into your Ascend app.
- **Every connection logged locally** - when, where, how many bytes - in a JSON-lines audit log.

## Install

| | |
|---|---|
| macOS | `brew install straiker-ai/tap/ascend-tunnel` |
| Windows | `winget install Straiker.AscendTunnel`, or `scoop bucket add straiker https://github.com/straiker-ai/scoop-bucket` then `scoop install ascend-tunnel` (no admin rights needed) |
| Linux | the `.deb` / `.rpm` from [Releases](../../releases) (installs a systemd service), or the archive |
| Docker | `docker run ghcr.io/straiker-ai/ascend-tunnel` (see [Running it as a service](#running-it-as-a-service)) |
| Anything else | the archive for your platform from [Releases](../../releases) - one static binary |

Package-manager channels go live with the first tagged release.

### Verify a download

Every release artifact has a signed build provenance attestation, tying it to the commit and the
workflow that built it:

```sh
gh attestation verify ascend-tunnel_<version>_<os>_<arch>.tar.gz --repo straiker-ai/ascend-tunnel
sha256sum -c checksums.txt --ignore-missing
```

Builds are reproducible. Rebuild a release binary from its tag, with the Go toolchain `go.mod` names,
and compare checksums:

```sh
git checkout v<version>
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=<version> -X main.commit=$(git rev-parse --short HEAD)" ./cmd/ascend-tunnel
```

Linux binaries match byte for byte. Windows and macOS release binaries additionally carry a code
signature, so compare them after removing it.

## Set up

You need your **Straiker org id** and the **host** of the app to reach from this machine (and its
port, if it is not 443).

1. **Check the path** - the relay through your proxy, its TLS, and your app:

   ```sh
   ascend-tunnel check --org 1234 --allow chat.corp.internal
   ```

   Every line should read `PASS`, except `WAIT` for the key (step 3). Paste the output to Straiker if
   anything fails.

2. **Run it:**

   ```sh
   ascend-tunnel --org 1234 --allow chat.corp.internal
   ```

   `--allow chat.corp.internal` means port 443; give `host:port` for any other. On first start the
   agent prints its key and the URL each target is reached at:

   ```
   {"event":"identity", ... "agent_key":"AAAAC3NzaC1lZDI1NTE5...",
    "app_urls":["https://chat.corp.internal.tun.straiker.ai"], ...}
   ```

   `ascend-tunnel key` prints the key on its own; `check` prints both.

3. **Authorize it in Ascend.** In the app's request template, set `_tunnel_agent_keys` to the key
   (a list, one entry per agent), and set the app's URL to its target's app URL plus the app's path:
   `https://chat.corp.internal.tun.straiker.ai/v1/chat`. Until an app lists the key the relay refuses the
   agent; it retries every ~5 seconds, so **Test connection** works as soon as the key is pasted.

More apps on the same agent: add each host with another `--allow`, and paste the same key into each
app. For availability, run a second agent and list both keys.

## Configuration

Flags override `TUNNEL_*` environment variables, which override the config file
(`-c agent.yaml`; by default `/etc/straiker/agent.yaml`, or
`%ProgramData%\Straiker\ascend-tunnel\agent.yaml` on Windows, when present). See
[config.example.yaml](config.example.yaml).

| flag | environment | file | default |
|---|---|---|---|
| `--org` | `TUNNEL_TENANT` | `tenant` | required |
| `--allow host[:port]` (repeat; port 443 if omitted) | `TUNNEL_ALLOW` (comma-separated) | `allow` | required |
| `--env` | `TUNNEL_ENV` | `env` | `prod` |
| `--relay` | `TUNNEL_RELAY` | `relay` | the environment's relay |
| `--host-key` | `TUNNEL_HOST_KEY` | `host_key` | the environment's pinned key |
| `--state-dir` | `TUNNEL_STATE_DIR` | `state_dir` | per user (below) |
| `--ca-file` | `TUNNEL_CA_FILE` | `ca_file` | none |
| `--audit-log` | `TUNNEL_AUDIT_LOG` | `audit_log` | `<state-dir>/connections.jsonl` |
| `--fanout` | `TUNNEL_FANOUT` | `fanout` | `1` |

The state directory holds the agent's private key; keep it, or the agent gets a new identity. By
default: `%LOCALAPPDATA%\Straiker\ascend-tunnel` on Windows, `~/Library/Application Support/Straiker/ascend-tunnel`
on macOS, `/var/lib/straiker-tunnel` for root on Linux, `~/.local/state/ascend-tunnel` otherwise.

### Corporate proxies and TLS inspection

The agent honours `HTTPS_PROXY` / `NO_PROXY` and trusts the operating system's certificate store,
so a proxy CA your IT has installed just works. If the proxy's CA is not in the system store, pass
it with `--ca-file`. The connection is an ordinary WebSocket over HTTPS, which inspecting proxies
pass. The relay's SSH host key is pinned inside that connection, so a proxy cannot impersonate it.

### Throughput

One link carries tens of concurrent connections. For more, raise `--fanout` (up to 16 links) or run
more agents.

## Running it as a service

- **Linux (deb/rpm):** edit `/etc/straiker/agent.yaml`, then `systemctl enable --now ascend-tunnel`.
  The unit runs it as a sandboxed dynamic user with its key in `/var/lib/ascend-tunnel`.
- **Docker:**

  ```sh
  docker run -d --name ascend-tunnel --restart unless-stopped \
    -v ascend-tunnel:/var/lib/ascend-tunnel \
    ghcr.io/straiker-ai/ascend-tunnel --org 1234 --allow chat.corp.internal
  ```

  The image is distroless and runs as uid 65532; keep the volume, it holds the key.
- **Windows and macOS:** run it in a terminal, or under your usual service manager. Keep the machine
  awake for the length of an assessment - a sleeping laptop pauses it.

## The audit log

One JSON object per line, also printed to stdout:

| event | when |
|---|---|
| `identity` | start: org, agent id, the key to paste |
| `waiting` | the relay refused the key (no app lists it yet); at most once a minute |
| `connected` / `forward` | a link is up, and each target's socket on it |
| `connection` | one per connection through the tunnel: target, bytes each way, duration |
| `disconnected` | a link dropped; it reconnects with backoff |

## Development

```sh
go test -race ./...
goreleaser release --snapshot --clean --skip=publish   # every archive, package and manifest
```

`testdata/contract.json` pins the names the agent and the relay must derive identically.

## License

[Apache 2.0](LICENSE)
