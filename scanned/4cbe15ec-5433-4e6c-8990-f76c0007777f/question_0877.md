# Q877: near valid messages reaching ChainDB repeatedly in dbMarkerParse

## Question
Can an unprivileged attacker reach dbMarkerParse with near-valid messages reaching ChainDB repeatedly and normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/DbMarker.hs / dbMarkerParse
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing.
- Exploit idea: Drive `dbMarkerParse` in `Ouroboros.Consensus.Node.DbMarker` through the production entrypoint using near-valid messages reaching ChainDB repeatedly; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Disconnect/reconnect and Genesis sync transitions must not leave stale peer state that affects chain selection.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
