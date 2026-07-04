# Q236: disconnect reconnect in realHeaderInFutureCheck

## Question
Can an unprivileged attacker reach realHeaderInFutureCheck with disconnect/reconnect with stale peer state and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/InFutureCheck.hs / realHeaderInFutureCheck
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `realHeaderInFutureCheck` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client.InFutureCheck` through the production entrypoint using disconnect/reconnect with stale peer state; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
