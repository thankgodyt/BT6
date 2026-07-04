# Q2202: disconnect reconnect in newChainSyncClientHandleCollection

## Question
Can an unprivileged attacker reach newChainSyncClientHandleCollection with disconnect/reconnect with stale peer state and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/State.hs / newChainSyncClientHandleCollection
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `newChainSyncClientHandleCollection` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client.State` through the production entrypoint using disconnect/reconnect with stale peer state; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
