# ascend-agent (experimental)

`ascend-agent` is a second binary in this repo. It runs on a machine inside your network and serves
**tools** to Straiker's cloud agents over one outbound HTTPS connection, under a policy file you own.
The agents (their prompts, models and reasoning) run in Straiker's cloud. The host only runs the narrow,
named tools you enable, against the targets you name.

> **Status: experimental.** The protocol (`agent/v0`, pinned in
> [`testdata/agent-contract.json`](../testdata/agent-contract.json)) may change between releases.

```
Straiker cloud agent ──► Straiker agent API ◄──── outbound HTTPS (SSE + POST) ──── ascend-agent ──► your targets
                         (session tokens)                                         (your policy)
```

## How it differs from ascend-tunnel

| | ascend-tunnel | ascend-agent |
|---|---|---|
| carries | bytes (TLS end to end, Ascend to your app) | tool calls (MCP JSON-RPC), and their results |
| used for | assessments of a private app | Straiker's cloud agents, e.g. building an adaptor for your app |
| you control it with | `--allow host[:port]` | a policy file: targets, packs, which agent may call which tool, limits |
| transport | WebSocket + SSH to the relay | Server-Sent Events down, HTTPS POST up; long-poll if a proxy buffers SSE |
| key | `agent.key` in the state directory | **the same key**: one machine, one identity |

## The safety model

- **Outbound only, no listening port.** The host dials out to Straiker's agent API on 443
  (`https://ascendai-bridge.prod.straiker.ai/agent/v1`, the host ascend-tunnel already reaches, so one
  egress rule covers both), through
  `HTTPS_PROXY` if set, trusting the system store plus an optional `ca_file`. Nothing on your network
  can call its tools.
- **Straiker sends arguments, never code.** Every tool is fixed code in this binary.
- **Targets by id.** A tool reaches only the targets your policy lists, and the cloud names them by id.
  `http.probe` accepts a path under the target, never a URL, and follows redirects only on the same
  host.
- **Effective permission = Straiker's grant ∩ your policy.** Every call carries a session token signed
  by Straiker. The host verifies it with the key pinned in your policy (`session_key`, plus
  `session_keys` during a rotation; EdDSA only), and checks it names this host, your org and the call's
  session, expires within the hour, and is **bound to that one call**: its `call_id` and the SHA-256 of
  the exact message (`msg_sha256`). A token cannot be replayed for another call or message. A tool is
  visible and callable only if your policy lists it for that agent **and** the token grants it.
- **Limits you set:** `concurrent_calls` and `calls_per_minute`, whatever a session asks for.
- **Everything logged locally**, in the same JSON-lines format as the tunnel's audit log
  (`<state-dir>/ascend-agent-audit.jsonl`): each session, each call (tool, a digest of its arguments, outcome,
  duration), refusals, and connection changes.
- **Redelivery is safe.** Each call has a `call_id`; a call Straiker re-sends gets the same answer
  without running again.

## Tools (v0)

| Tool | Does |
|---|---|
| `env.info` | version, platform, target ids, tools served, policy digest, whether a proxy is used |
| `net.check` | TCP connect to a target and, for https, a TLS handshake, reporting whether the certificate verifies; sends no request |
| `http.probe` | one GET to a path under a target, with no cookies or credentials: status, selected headers, title, up to 256 KiB of text |
| `ascend.apps`, `ascend.runs`, `ascend.run` | your Ascend applications and assessment runs, read with your own login |
| `ascend.app_create` | creates an Ascend application with your own login, only after you confirm in the terminal; returns the applications already on that endpoint or name instead of a duplicate. Offered only in `ascend-agent` chat, and only to Ascend Agent (not the builder) |
| `ascend.app_adaptor` | stores an adaptor on one of your applications with your own login (in its request template, under `_adaptor_src`), only after you confirm in the terminal; refuses if the application's name doesn't match, and checks that Straiker kept it. Ascend Agent sends only what the adaptor builder proposed and tested. Offered only in `ascend-agent` chat, and only to Ascend Agent |
| `tunnel.open` | lets Straiker reach an app only your network reaches, through this machine, while `ascend-agent` runs (ascend-tunnel built in, with this machine's key), only after you confirm in the terminal; returns the tunnel endpoint and agent key for the application. Offered only in `ascend-agent` chat, only to Ascend Agent, and only within the policy's `interactive.allow_hosts` |

## Policy

```yaml
org: "1234"                       # your Straiker org id
env: prod                         # or api: <agent API base URL>
session_key: "<the key Straiker publishes for your environment>"
# session_keys: ["<next key>"]   # during a rotation, both verify
# ca_file: /etc/ssl/corp-proxy.pem

targets:                          # what tools may reach; the cloud only ever sends the id
  support-bot: { url: "https://support.corp.example/" }
  intranet-api: { url: "http://10.0.0.5:8080/api/" }

packs: [env, net, http]           # tool packs to turn on (env, net, http, browser, ascend, tunnel)

agents:                           # which Straiker agent may call what: <pack>.<tool> or <pack>.*
  ascend: [env.info, net.check]                       # Ascend Agent itself
  adaptor-builder: [env.info, net.check, http.probe]  # the adaptor builder, during a build

limits: { concurrent_calls: 4, calls_per_minute: 120 }
# audit: { file: /var/log/straiker/ascend-agent-audit.jsonl }
```

Unknown keys are refused, as are targets with credentials, a query or a fragment, unknown packs, and
agent patterns naming a pack that is not on.

```bash
ascend-agent policy check -policy ascend-agent.yaml   # validate, with warnings
ascend-agent policy show  -policy ascend-agent.yaml   # targets, tools, what each agent may call
```

## Running it

Install it with `brew install straiker-ai/tap/ascend-tunnel straiker-ai/tap/ascend-agent` (Homebrew loads
only the casks you name from a tap you haven't trusted, so name both; or run `brew trust straiker-ai/tap` once,
and `brew install straiker-ai/tap/ascend-agent` brings `ascend-tunnel` with it). Or download it from
[Releases](https://github.com/straiker-ai/ascend-tunnel/releases), or `go build -o ascend-agent ./cmd/ascend-agent`.
Then:

```bash
ascend-agent key                          # this machine's key (the tunnel's), to enrol the host
ascend-agent run -policy ascend-agent.yaml        # serve Straiker's cloud agents
ascend-agent serve -stdio -policy ascend-agent.yaml   # the same tools over stdio, for an MCP inspector
```

`serve -stdio` speaks MCP's standard stdio transport, so you can look at exactly what Straiker's
agents would be offered (with every enabled tool visible) before running the host. Point any MCP
client at the command, e.g. the MCP Inspector.

Flags override the policy: `-org`, `-env`, `-api`, `-session-key`, `-ca-file`, `-state-dir`,
`-audit-log`. The policy file is `-policy`, else `ASCEND_AGENT_POLICY`, else `/etc/straiker/ascend-agent.yaml`
(`%ProgramData%\Straiker\ascend-agent\policy.yaml` on Windows).

## Talking to Ascend Agent

```text
ascend-agent login     # once: paste a Straiker personal access token
ascend-agent           # talk; approve sites when an agent first wants to reach them
```

`login` keeps the token in `~/.ascend-agent/config.json` (mode 0600), with the environment, org and user it signs
in as, and pins Straiker's session key on first use. `STRAIKER_API_KEY` overrides the saved token for scripts.

`ascend-agent` enrols this machine for your org the first time (it asks), and serves the agents' tools while it
runs. With no policy file, nothing is reachable until you approve it: the first time an agent wants a site, the
terminal asks `[y] this session / [a] always / [n] no`. Sites you always allow are kept per org in
`~/.ascend-agent/sites.json`; `/sites` lists them and `/sites forget <host>` asks again. Every call on this
machine shows in the conversation, marked `on this machine`. Link-local and cloud-metadata addresses are never
reachable.

Everything the cloud sends is stripped of terminal escape sequences before it is printed.

### Recording a browser session for the agent

When the agent needs to see a chat that only works in a real browser (a widget, a login, a bot wall), it can open
one for you (`browser.capture`, after you approve the site). The window is visible and uses Ascend's own browser
profile in `~/.ascend-agent/browser`: separate from your everyday browsing, and kept between captures so a login
there survives. You do what the agent asks in it (open the chat, send a message); nothing is clicked for you.
Type `/done`, or close the window, and the recording becomes a HAR here, with cookie values, auth headers and
password- or token-like fields removed before it leaves the machine. A copy is kept in `~/.ascend-agent/captures`.
It needs Chrome, Edge, Brave or Chromium (`ASCEND_AGENT_BROWSER` names one); without one, export a HAR from your
browser's DevTools and attach it with `/har`.

### Your Ascend data

Ask about your assessments ("how have the runs on my support-bot app been trending?") and the agent reads them through
this machine, with your own login: the `ascend` tools make fixed, read-only calls to Straiker's API (your
applications, an application's runs, one run). The cloud sends only ids, and your token never leaves this
machine, so the agent sees exactly what you can.

### Connecting an application

Say `connect <your chat API's URL> as <name>`. Ascend Agent looks for an application already on that endpoint and
offers it; otherwise it works out the request and asks you to confirm before anything is created:

```text
? Allow Ascend Agent to create the Ascend application "support-bot" for https://chat.example.com/v1/chat in org 1 (small, 30 queries a minute, 42 controls)?
  [y] yes   [n] no
```

If the API needs a key, you type it at a masked prompt in the terminal: it goes to Straiker with the application,
and Ascend Agent never sees it. `/apps` lists your applications without asking the agent.

Ascend Agent checks the endpoint first. A known agent platform (Salesforce Agentforce, Amazon Bedrock, Azure AI
Foundry, Google Cloud, Copilot Studio, ChatGPT) goes to its Straiker Defend onboarding page instead. An endpoint
Straiker's cloud cannot reach (an internal name, or private addresses only) needs a tunnel, and Ascend Agent offers
one through this machine, with nothing else to install:

```text
? Allow Ascend Agent to let Straiker's cloud reach chat.corp.internal:443 through this machine while ascend-agent runs (org 1)?
  [y] yes   [n] no
```

The application is then created on the tunnel's address with this machine's key. While a tunnel is open, the status
bar shows it (`⇄ chat.corp.internal:443`); `/tunnel` lists what Straiker reaches through this machine and how many
connections it made, and `/tunnel close` (or `/tunnel close <host>`) stops it at once. The tunnel runs only while
`ascend-agent` does; when you leave, it prints the command that keeps it running as a service, with the same key
(so the application keeps working): `ascend-tunnel service install --org 1 --allow chat.corp.internal:443`.

If the API needs more than one plain request per message (a login step, a session id carried between turns, a
streamed reply), the adaptor builder writes an adaptor for it, and Ascend Agent offers to store it on the application;
you confirm, and it runs one conversation through the stored adaptor to check.

### Your organisation's daily budget

Ascend Agent's model use is capped per organisation per UTC day, and refreshes at 00:00 UTC. The banner and the
status bar show today's use; `/usage` shows what is left.

### A policy file caps what can be approved

On a managed machine, put a policy file at the default path (or pass `-policy`). Its targets need no approval,
and `interactive.allow_hosts` says what a person may approve beyond them; a file without it allows no approvals:

```yaml
targets:
  support: { url: "https://support.example.com/" }
interactive:
  allow_hosts: ["*.example.com"]     # "*" for any site; omit to allow none
```

`ascend-agent run` serves the same tools unattended. Nobody is there to approve anything, so it reaches only
the file's targets.

## The protocol (agent/v0)

Pinned in [`testdata/agent-contract.json`](../testdata/agent-contract.json).

- `GET {base}/stream`: Server-Sent Events. `event: call` carries an envelope
  `{sid, call_id, session_jwt, timeout_ms?, message}` where `message` is an MCP JSON-RPC message;
  `event: close` ends a session (`{sid}`); heartbeats at least every 15 s. Resumes with `Last-Event-ID`.
- `GET {base}/poll?wait=25&after=<id>`: the same events as JSON `{events: [...]}`, used when no
  heartbeat arrives within 20 s of connecting (a proxy buffering SSE). The stream is retried every
  10 minutes.
- `POST {base}/results`: `{sid, call_id, message}`, the MCP response.
- `POST {base}/hello`: on each connect, what this host serves (agent id, org, version, policy digest,
  tool names, target ids).
- Every request carries `Authorization: Bearer <host token>`: an EdDSA JWS signed with the machine key
  (`sub` = agent id, `aud` = `ascend-agent-api`, `tenant`, 5-minute expiry), and
  `X-Ascend-Agent-Protocol: agent/v0`.
- Each call's `session_jwt` is call-bound: claims `call_id` and `msg_sha256` = lowercase hex SHA-256
  of the message's compact JSON (test vectors in the contract file).
- Refusals before a tool runs are JSON-RPC errors: `-32001` session token rejected, `-32002`
  `calls_per_minute` reached, `-32003` `concurrent_calls` busy for the whole call time.

## Code

| Package | What |
|---|---|
| `cmd/ascend-agent` | the command |
| `internal/agenthost` | the host role: verify, limit, dedupe, serve, audit, post |
| `internal/agenthost/wire` | protocol names and shapes (pinned by the contract test) |
| `internal/agenthost/stream` | SSE stream, long-poll fallback, POSTs, backoff |
| `internal/agenthost/mcp` | the MCP server (JSON-RPC: initialize, ping, tools/list, tools/call, cancellation) |
| `internal/agenthost/packs` | the tools |
| `internal/agenthost/policy` | the policy file |
| `internal/agenthost/token` | host tokens (minted with the machine key) and session tokens (verified) |
| `internal/agenthost/netx` | TLS and proxy settings |

It reuses `internal/identity` (the machine key) and `internal/agent`'s audit log, so the host and the
tunnel share one identity and one audit format.
