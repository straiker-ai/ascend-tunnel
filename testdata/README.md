# Test data

- `contract.json` - the names the agent and Straiker's relay must derive identically (agent id,
  relay login, socket directory and paths). Generated from the relay's reference implementation;
  the relay's tests check the same file, so a change here must land on both sides.
- `agent-contract.json` - the `ascend-agent` wire protocol (paths, events, envelope fields, token claims,
  error codes), checked by `internal/agenthost/wire`'s contract test. Straiker's agent API must check the
  same file. See `docs/ascend-agent.md`.
