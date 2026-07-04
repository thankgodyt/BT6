# Q2801: duplicate object diffusion data before block context exists in intersectFound

## Question
Can an unprivileged attacker reach intersectFound with duplicate object-diffusion data before block context exists and near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs / intersectFound
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: near-valid headers, stale fragments, future-slot announcements, object identifiers, block fetch responses, and peer churn under normal protocol behavior.
- Exploit idea: Drive `intersectFound` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client` through the production entrypoint using duplicate object-diffusion data before block context exists; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Near-valid protocol messages must be rejected before expensive consensus/storage work repeats indefinitely.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
