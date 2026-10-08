# Test data

- `contract.json` - the names the agent and Straiker's relay must derive identically (agent id,
  relay login, socket directory and paths). Generated from the relay's reference implementation;
  the relay's tests check the same file, so a change here must land on both sides.
- `python-agent.key` - a **throwaway test key**, written by the earlier Python agent, never listed
  anywhere. It proves an existing install keeps its identity when it moves to this agent.
