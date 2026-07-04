# Q2534: duplicate object diffusion data before block context exists in Ouroboros Conse

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API with duplicate object-diffusion data before block context exists and near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/API.hs / Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior.
- Exploit idea: Drive `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API` in `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API` through the production entrypoint using duplicate object-diffusion data before block context exists; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Near-valid protocol messages must be rejected before expensive consensus/storage work repeats indefinitely.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
