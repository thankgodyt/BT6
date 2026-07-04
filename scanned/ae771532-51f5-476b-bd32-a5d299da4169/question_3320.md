# Q3320: withheld BlockFetch bodies in NodeInitStorage

## Question
Can an unprivileged attacker reach NodeInitStorage with withheld BlockFetch bodies after ChainSync headers and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then force repeated expensive validation before decisive rejection in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Node/InitStorage.hs / NodeInitStorage
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `NodeInitStorage` in `Ouroboros.Consensus.Node.InitStorage` through the production entrypoint using withheld BlockFetch bodies after ChainSync headers; verify whether the path can force repeated expensive validation before decisive rejection before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
