# Q2523: near valid messages reaching ChainDB repeatedly in getCandidates

## Question
Can an unprivileged attacker reach getCandidates with near-valid messages reaching ChainDB repeatedly and normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs / getCandidates
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing.
- Exploit idea: Drive `getCandidates` in `Ouroboros.Consensus.MiniProtocol.BlockFetch.ClientInterface` through the production entrypoint using near-valid messages reaching ChainDB repeatedly; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Disconnect/reconnect and Genesis sync transitions must not leave stale peer state that affects chain selection.
- Expected Cardano/Intersect impact: Potential Medium if a public node API or miniprotocol path exposes sensitive consensus state or weakens validation assumptions.
- Fast validation: Fuzz node-to-node messages and version negotiation while measuring known-invalid deduplication before expensive validation.
