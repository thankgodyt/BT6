# Q226: duplicate object diffusion data before block context exists in cleanShutdownMa

## Question
Can an unprivileged attacker reach cleanShutdownMarkerFile with duplicate object-diffusion data before block context exists and near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Recovery.hs / cleanShutdownMarkerFile
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior.
- Exploit idea: Drive `cleanShutdownMarkerFile` in `Ouroboros.Consensus.Node.Recovery` through the production entrypoint using duplicate object-diffusion data before block context exists; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Near-valid protocol messages must be rejected before expensive consensus/storage work repeats indefinitely.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
