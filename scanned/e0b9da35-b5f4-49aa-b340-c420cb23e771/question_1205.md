# Q1205: withheld BlockFetch bodies in Ouroboros Consensus Node DbMarker

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Node.DbMarker with withheld BlockFetch bodies after ChainSync headers and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then reuse stale validation or ledger context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/DbMarker.hs / Ouroboros.Consensus.Node.DbMarker
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `Ouroboros.Consensus.Node.DbMarker` in `Ouroboros.Consensus.Node.DbMarker` through the production entrypoint using withheld BlockFetch bodies after ChainSync headers; verify whether the path can reuse stale validation or ledger context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
