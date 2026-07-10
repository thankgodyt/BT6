Looking at the bridge's pause mechanism, I need to find a function that should be protected by the pause guard but isn't — the direct analog to the external report's "missing opcode in pause check."

Let me check the full list of public state-changing functions and their pause decorators in `bridge.rs`: