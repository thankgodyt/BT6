# Q983: same fragments delivered in different valid orders in VersionDecoder

## Question
Can an unprivileged attacker reach VersionDecoder with same fragments delivered in different valid orders and valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Versioned.hs / VersionDecoder
- Entrypoint: Remote peer or local public client reaches this production consensus path with protocol-valid or near-valid data through supported node interfaces.
- Attacker controls: valid-looking protocol data, duplicate inputs, boundary values, stale state, and competing arrival order.
- Exploit idea: Drive `VersionDecoder` in `Ouroboros.Consensus.Util.Versioned` through the production entrypoint using same fragments delivered in different valid orders; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Boundary values for slots, points, hashes, and fragments must not cause accepted state to diverge across validation paths.
- Expected Cardano/Intersect impact: Potential Medium if near-valid data creates sustained resource exhaustion without prohibited flood-style DoS.
- Fast validation: Fuzz boundary slots, points, hashes, and serialized values and assert rejection happens before partial state update.
