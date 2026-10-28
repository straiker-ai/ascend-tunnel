# ascend-tunnel

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/straiker-ai/ascend-tunnel/badge)](https://scorecard.dev/viewer/?uri=github.com/straiker-ai/ascend-tunnel)

The Straiker Ascend tunnel agent. Run it on any machine inside your network that can reach the AI
app you want to red-team, and Ascend reaches that app through one outbound HTTPS connection - no
inbound ports, no VPN, no DNS or cloud changes.

```
Straiker Ascend ──► Straiker relay ◄──── outbound HTTPS (WebSocket) ──── ascend-tunnel ──► your app
                                                                         (your network)
        └──────────────── TLS end to end, Ascend to your (HTTPS) app ────────────────┘
```

- **Outbound only.** The agent dials out to Straiker's relay on 443, through your proxy if you have
  one. Nothing connects in.
- **Reaches only what you list.** Each `--allow host[:port]` is one fixed forward; the agent dials
  nothing else, whatever it is asked.
- **Sees only ciphertext, for HTTPS apps.** TLS runs end to end from Ascend to your app; the agent
  splices bytes. A plain-HTTP app's traffic is carried as it is, inside the encrypted tunnel.
- **Your key, on your machine.** The agent generates its key on first start and never sends the
  private half anywhere. You authorize it by pasting the public half into your Ascend app.
- **Every connection logged locally** - when, where, how many bytes - in a JSON-lines audit log.

## Install

| | |
|---|---|
| macOS | `brew install straiker-ai/tap/ascend-tunnel` (`straiker-ai/tap/ascend-agent` installs [ascend-agent](docs/ascend-agent.md) and the tunnel with it) |
| Windows | the `.zip` from [Releases](../../releases) |
| Linux | the `.deb` / `.rpm` from [Releases](../../releases) (installs a systemd service), or the archive |
| Docker | `docker run ghcr.io/straiker-ai/ascend-tunnel` (see [Running it as a service](#running-it-as-a-service)) |
| Anything else | the archive for your platform from [Releases](../../releases) - one static binary |

macOS binaries are signed with Straiker's Developer ID and notarized by Apple. Windows binaries aren't Authenticode-signed yet (see [Releasing](#releasing)). The Homebrew casks are generated and published by the release, once it is published (`scripts/publish-casks.sh`); nobody edits [straiker-ai/homebrew-tap](https://github.com/straiker-ai/homebrew-tap) by hand. winget and Scoop manifests are generated but not published yet: their repositories don't exist (see `.goreleaser.yaml`).

### Verify a download

Every release artifact has a signed build provenance attestation, tying it to the commit and the
workflow that built it:

```sh
gh attestation verify ascend-tunnel_<version>_<os>_<arch>.tar.gz --repo straiker-ai/ascend-tunnel
sha256sum -c checksums.txt --ignore-missing
```

Scanners that match whole Go modules report a finding or two that does not apply to these binaries. Each
release publishes why in `ascend-tunnel.openvex.json` (OpenVEX), which most scanners read:
`trivy rootfs --vex ascend-tunnel.openvex.json <binary>`.

Each archive has an SPDX SBOM beside it (`<archive>.sbom.json`), and the container image carries an SBOM and
build provenance as attestations (`docker buildx imagetools inspect ghcr.io/straiker-ai/ascend-tunnel:<version>
--format '{{ json .SBOM }}'`).

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

Four steps, in order. Each names who it involves and what you should see before moving on.

**Before you start**, have:

- your **Straiker org id**;
- the **host** of each app to reach, and its port if it is not 443 - see
  [what goes in `--allow`](#what-goes-in---allow);
- a **machine** inside your network that can reach those apps and stays on during assessments, with
  the agent [installed](#install). A server or VM is best: a laptop that sleeps, or a virtual desktop
  that resets at logoff, stops the tunnel.

Run every command on that machine. Using Docker? Follow
[the same steps with Docker](#the-same-steps-with-docker).

### Step 1 - Check the tunnel (network team)

```sh
ascend-tunnel check tunnel --org 1234
```

Tests this machine's path to Straiker one hop at a time: DNS, TCP, your proxy, TLS, HTTPS, WebSocket,
and the relay's identity. It installs and saves nothing.

**Done when:** `RESULT PASS: this machine reaches Straiker` (or `RESULT WAIT` if the agent has run
here before: the path is fine, its key is just not in an app yet). If a step fails, the `->` line under it
says what to ask for - usually outbound HTTPS to `ascendai-bridge.prod.straiker.ai`, allowed by
hostname, with WebSocket allowed. Not sure whether you have a proxy? The check lists proxy settings on
this machine that the agent is not using, and tries the proxy they name. See
[Troubleshooting](#troubleshooting).

### Step 2 - Check the apps (app owner)

```sh
ascend-tunnel check app --allow chat.corp.internal
```

Tests that this machine reaches each app, and whether it speaks TLS or plain HTTP. Give `host:port`
for a port other than 443, and repeat `--allow` for more apps. It never contacts Straiker.

**Done when:** `RESULT PASS`. Note each app's **app URL**, e.g.
`https://chat.corp.internal.tun.straiker.ai` - step 4 uses it. A `WARN` that an app speaks plain HTTP
means its app URL starts with `http://` instead.

### Step 3 - Run the agent (machine owner)

Steps 1 and 2 only checked. Now start the agent for real, as a service that keeps running for your
assessments, with the same org and allowlist - see [Running it as a service](#running-it-as-a-service).
On its first start it creates its key in its state directory (the private half never leaves this
machine) and logs it:

```
{"event":"identity", ... "agent_key":"AAAAC3NzaC1lZDI1NTE5...", ...}
```

**Done when:** you have copied `agent_key` from the agent's log. Until step 4 the agent logs `waiting`
once a minute - expected.

The agent keeps this key across restarts and upgrades, so you paste it once. It gets a new key only
if its state directory is lost (for example, a Docker container removed without its volume); then
paste the new one.

### Step 4 - Connect the app in Ascend (Ascend user)

In the app's settings in Ascend:

- **URL:** the app URL from step 2 plus the app's path, e.g.
  `https://chat.corp.internal.tun.straiker.ai/v1/chat`. No port: it lives in `--allow`.
- **Request template:** add the key, as a list with one entry per agent:
  `"_tunnel_agent_keys": ["AAAAC3NzaC1lZDI1NTE5..."]`. To have Ascend verify an app whose certificate
  is from a private CA, also add that CA: `"_tunnel_ca": "<PEM>"`.

Click **Test connection**.

**Done when:** Test connection passes - that proves the whole path, and setup is done. Within seconds
the agent logs `connected`, then one `connection` line per request.

Then run assessments in Ascend, and keep the agent running while they do. More apps: add each host to
`--allow`, restart the agent, and repeat step 4 with the same key. For availability, run a second
agent and list both keys.

### The same steps with Docker

Docker Desktop includes the `docker` command (its **Terminal** button opens one). A container uses
neither this machine's proxy settings nor its certificate store, so if you have a proxy, add
`-e HTTPS_PROXY=http://proxy.corp:8080` to every command, and if it inspects TLS, mount its CA
(`-v /path/to/ca.pem:/ca.pem:ro`, then `--ca-file /ca.pem`).

1. **Check the tunnel** - saves nothing, so no volume:

   ```sh
   docker run --rm ghcr.io/straiker-ai/ascend-tunnel check tunnel --org 1234
   ```

2. **Check the apps.** In a container, `localhost` is the container itself: for an app on this
   machine, allow `host.docker.internal` (or see
   [an app that must be called `localhost`](#an-app-that-must-be-called-localhost)).

   ```sh
   docker run --rm ghcr.io/straiker-ai/ascend-tunnel check app --allow chat.corp.internal
   ```

3. **Run the agent**, with a volume for its key, and read the key:

   ```sh
   docker run -d --name ascend-tunnel --restart unless-stopped \
     -v ascend-tunnel:/var/lib/ascend-tunnel \
     ghcr.io/straiker-ai/ascend-tunnel --org 1234 --allow chat.corp.internal
   docker logs ascend-tunnel | grep identity
   ```

   (In PowerShell, `| Select-String identity` instead of `| grep identity`.) The volume holds the
   key: a new container with the same volume keeps it; without it, the agent makes a new key.

   **From Docker Desktop's window instead:** pull the image once
   (`docker pull ghcr.io/straiker-ai/ascend-tunnel`), then **Images**, **Run**, **Optional settings**:
   container name `ascend-tunnel`; environment variables `TUNNEL_TENANT` = your org id and
   `TUNNEL_ALLOW` = your apps (comma-separated); a volume with container path
   `/var/lib/ascend-tunnel` and a folder of your choice as host path. The key is in the container's
   **Logs** tab. Docker Desktop does not start it again on its own: after Docker Desktop restarts,
   click **Start** on the container.

4. **Connect the app in Ascend** - exactly as in step 4 above. Test connection passing ends setup.

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

### What goes in `--allow`

Each entry is one app, as this machine reaches it: `host` (port 443) or `host:port`. The host is a
hostname or an IPv4 address - not an IPv6 address, a wildcard or a range. One entry per host (for
two ports on one host, see [below](#two-ports-on-one-host)).

The agent resolves the host with this machine's own DNS (its hosts file, then your DNS servers) when
it connects, not once at start, and dials it directly - never through the proxy. `check app` dials
the same way, so if it passes, the agent reaches the app too.

**The port stays with the agent.** The app URL names only the host: Ascend reaches every app at its
tunnel name, and the agent dials the `host:port` of the matching entry, so the port appears nowhere
in Ascend. Moving the app to another port means changing the entry and restarting the agent; the app
in Ascend stays as it is. What Ascend does need is the URL's scheme: `https://` if the app speaks
TLS on that port, `http://` if not - `check app` says which.

The host is also the app's name on Ascend's side: the app URL is `https://<host>.tun.straiker.ai`, and
Ascend sends `<host>` as the `Host` header (with no port) and, over TLS, as the server name. So allow
the name the app answers to:

- If this machine cannot resolve that name, add it to the machine's hosts file rather than allowing
  an IP. In Docker, add it to the container instead: `--add-host chat.corp.internal:10.0.4.12`.
- An IP works for an app that answers on any name. Ascend sends no server name to an IP, and a
  `_tunnel_ca` then verifies the certificate only if the certificate lists that IP. An app that picks
  a site by name, or a certificate issued only for a name, needs the name.
- In Docker, `localhost` is the container itself: for an app on this machine, allow
  `host.docker.internal` - unless the app must be called `localhost` (next).

#### An app that must be called `localhost`

Some test apps accept only `Host: localhost`. Give the agent `localhost` as the host, so the app URL
is `http://localhost.tun.straiker.ai/...` (or `https://`). The agent must then see the app at
`localhost`:

- **Run the agent on the app's machine, outside Docker:** `ascend-tunnel --org 1234 --allow
  localhost:8089`. A port a container publishes on that machine counts.
- **Or, when the app is a container, run the agent in the app container's network**, with the port
  the app listens on inside its container (not the published one):

  ```sh
  docker run -d --name ascend-tunnel-app --restart unless-stopped \
    --network container:<app container> \
    -v ascend-tunnel-app:/var/lib/ascend-tunnel \
    ghcr.io/straiker-ai/ascend-tunnel --org 1234 --allow localhost:8000
  ```

  It gets its own key (paste it into the app); if the app container is recreated, restart this one.

Ascend sends `Host: localhost` with no port, so an app that insists on `localhost:8089` refuses it.

#### Two ports on one host

The app URL carries no port, so one name can be allowed on one port only. Give the second port a
second name that reaches the same machine, allow that, and use it in the second app's URL:

- in Docker, `--add-host app2.internal:host-gateway --allow app2.internal:8089`;
- on the machine itself, a hosts-file line `127.0.0.1 app2.internal`, and `--allow
  app2.internal:8089`.

The second app's URL is then `http://app2.internal.tun.straiker.ai/...`.

#### More than one agent

- **For one app** (availability): every agent the app lists must allow the same `host:port` - Ascend
  spreads the app's traffic across all of them.
- **On one machine**: give each agent its own state directory or volume. Agents sharing a key are one
  identity to the relay, and their forwards for the same host collide.

### Corporate proxies and TLS inspection

The agent reaches the relay through `HTTPS_PROXY` (an `http://`, `https://` or `socks5://` URL;
credentials as `http://user:password@proxy:port`), honours `NO_PROXY`, and trusts the operating
system's certificate store, so a proxy CA your IT has installed just works. If the proxy's CA is not
in the system store, pass it with `--ca-file`. The connection is an ordinary WebSocket over HTTPS,
which inspecting proxies pass. The relay's SSH host key is pinned inside that connection, so a proxy
cannot impersonate it. Targets are always dialled directly, never through the proxy.

Not supported: the operating system's proxy settings and PAC files - set `HTTPS_PROXY` instead;
`check tunnel` lists the ones the agent is not using (also `HTTP_PROXY`, which it does not read for
HTTPS), and tries the proxy they name - and NTLM or Kerberos proxy authentication: ask for the
relay's host to be exempt from it (`check` names the scheme a proxy asks for). In Docker, pass `-e HTTPS_PROXY=...` and mount any CA: a container uses neither this machine's
proxy settings nor its certificate store.

### Throughput

One link carries tens of concurrent connections. For more, raise `--fanout` (up to 16 links) or run
more agents.

## Running it as a service

How to start the agent (step 3), read its key, and check with its key (when troubleshooting), on each
platform:

- **Linux (deb/rpm):** put your org id and allowlist in `/etc/straiker/agent.yaml`, then
  `sudo systemctl enable --now ascend-tunnel`. It runs as a sandboxed dynamic user with its key in
  `/var/lib/ascend-tunnel`.
  - Key: `journalctl -u ascend-tunnel | grep identity`
  - Check: `sudo ascend-tunnel check -c /etc/straiker/agent.yaml --state-dir /var/lib/ascend-tunnel`
- **Docker:** see [the same steps with Docker](#the-same-steps-with-docker). The image is distroless
  (no shell) and runs as uid 65532.
- **Windows and macOS:** `ascend-tunnel --org 1234 --allow chat.corp.internal` in a terminal, or
  under your usual service manager. Keep the machine awake for the length of an assessment.
  - Key: printed when it starts, or `ascend-tunnel key`
  - Check: `ascend-tunnel check --org 1234 --allow chat.corp.internal`, as the same user

## Troubleshooting

When Test connection fails, or a run pauses because the agent is unavailable, run the full check with
the agent's own key, on the machine (or in the container) it runs on - see
[Running it as a service](#running-it-as-a-service) for the command on each platform; with Docker:

```sh
docker run --rm --volumes-from ascend-tunnel ghcr.io/straiker-ai/ascend-tunnel check --org 1234 --allow chat.corp.internal
```

Healthy is `RESULT PASS` for both halves, with the `login` step saying an app lists this agent's key.
Otherwise its first `FAIL` is the answer, and the `->` line under it is what to do.

| step | fails when | usually |
|---|---|---|
| `dns` | the relay's host does not resolve, or resolves to `0.0.0.0` | a DNS filter blocks it |
| `tcp` | nothing answers on 443 | a firewall drops it, or this network needs a proxy; `check` also tries `www.microsoft.com:443` to tell which, and the proxy this machine's settings name |
| `tcp` | some of the relay's addresses answer, some do not | a firewall rule by hostname that resolved a stale set of addresses |
| `proxy` | the proxy answers `403`, `407` or `5xx` | its policy, credentials, or its own access to the relay |
| `tls` | the connection is cut right after the TLS hello | filtering by name (SNI / URL category) |
| `tls` | the certificate is from an unknown CA | TLS inspection: pass that CA with `--ca-file` |
| `https` | something other than the relay answers | a block page or web filter; a `407` is a proxy this network expects you to use |
| `websocket` | HTTPS works, the WebSocket upgrade does not | application control (e.g. Palo Alto App-ID `websocket`), or a TLS-inspecting proxy that strips the `Upgrade` header |
| `tunnel` | the WebSocket opens, then is cut | inspection of WebSocket traffic |
| `login` | `WAIT` | the key is not in an app yet, `--org` is not the app's org, or the key changed (new state dir) |

The running agent logs the same diagnosis once per outage, as a `diagnosis` event; with Docker,
`docker logs ascend-tunnel` (or Docker Desktop's Logs tab) shows it.

`ping` does not help: the relay does not answer ping, even when it is reachable.

## The audit log

One JSON object per line, also printed to stdout:

| event | when |
|---|---|
| `identity` | start: org, agent id, the key to paste |
| `waiting` | the relay refused the key (no app lists it yet); at most once a minute |
| `connected` / `forward` | a link is up, and each target's socket on it |
| `connection` | one per connection through the tunnel: target, bytes each way, duration |
| `disconnected` | a link dropped, after `up_s` seconds up; it reconnects with backoff. Drops after the same `up_s` again and again point to a proxy's connection time limit |
| `diagnosis` | once per outage, when the relay cannot be reached: where the path stops, and the fix |

## Development

```sh
go test -race ./...
go test ./internal/agenthost/token -run '^$' -fuzz FuzzVerifySession   # or any Fuzz* target; CI runs each 30s
goreleaser release --snapshot --clean --skip=publish   # every archive, package and manifest
```

`testdata/contract.json` pins the names the agent and the relay must derive identically.

### Releasing

Push a `v*` tag. It releases both binaries, `ascend-tunnel` and `ascend-agent`, signed the same way.
`.github/workflows/release.yml` builds on a macOS runner and reads its credentials from the `release` environment,
which only `v*` tags may use:

| | Kind | What |
|---|---|---|
| `MACOS_APP_P12`, `MACOS_APP_P12_PASSWORD` | secret | Straiker's Developer ID Application certificate, base64 `.p12`, and its password |
| `APPLE_APP_PASSWORD` | secret | app-specific password of `APPLE_ID`, for `notarytool` |
| `APPLE_ID` | secret | the Apple ID that notarizes (a secret so the public run logs mask it) |
| `APPLE_TEAM_ID` | variable | Straiker's Apple team id (public: it is in every signed binary) |
| `JSIGN_*` | secret | Windows Authenticode through a cloud HSM (`scripts/sign-windows.sh`); optional |
| `TAP_APP_CLIENT_ID` | variable | client ID of the tap-publisher GitHub App, installed on straiker-ai/homebrew-tap only with Contents: read and write |
| `TAP_APP_PRIVATE_KEY` | secret | that App's private key. The job mints a token for homebrew-tap only, to publish the casks after the release. Required on a release tag; prerelease tags (`v1.2.3-rc.1`) never touch the tap |

A tag fails if macOS signing or
notarization is missing, rather than publishing binaries Gatekeeper would block. Windows signing stays optional
until Straiker has an OV code-signing certificate in a cloud HSM.

## License

[Apache 2.0](LICENSE)
