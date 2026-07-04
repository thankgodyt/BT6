# Q1227: malicious and honest peers racing competing fragments in ObjectPoolReader

## Question
Can an unprivileged attacker reach ObjectPoolReader with malicious and honest peers racing competing fragments and near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/API.hs / ObjectPoolReader
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior.
- Exploit idea: Drive `ObjectPoolReader` in `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API` through the production entrypoint using malicious and honest peers racing competing fragments; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Near-valid protocol messages must be rejected before expensive consensus/storage work repeats indefinitely.
- Expected Cardano/Intersect impact: Potential High if adversarial peer scheduling makes honest nodes prefer different chains or starves valid block processing.
- Fast validation: Create an io-sim network with malicious and honest peers delivering headers, blocks, rollbacks, and disconnects in adversarial order.
