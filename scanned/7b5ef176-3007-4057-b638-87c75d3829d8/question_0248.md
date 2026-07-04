# Q248: withheld BlockFetch bodies in Ouroboros Consensus Node Run

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Node.Run with withheld BlockFetch bodies after ChainSync headers and ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers, then cause honest nodes to select different tips in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Node/Run.hs / Ouroboros.Consensus.Node.Run
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: ChainSync headers, rollback messages, BlockFetch bodies, peer disconnects, duplicate messages, object-diffusion items, and timing of competing peers.
- Exploit idea: Drive `Ouroboros.Consensus.Node.Run` in `Ouroboros.Consensus.Node.Run` through the production entrypoint using withheld BlockFetch bodies after ChainSync headers; verify whether the path can cause honest nodes to select different tips before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Peer-delivered headers, blocks, rollbacks, and object-diffusion items must not make consensus select different chains on honest nodes.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
