# Q1022: VRF KES OCert evidence at an epoch boundary in Bft

## Question
Can an unprivileged attacker reach Bft with VRF/KES/OCert evidence at an epoch boundary and block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/BFT.hs / Bft
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags.
- Exploit idea: Drive `Bft` in `Ouroboros.Consensus.Protocol.BFT` through the production entrypoint using VRF/KES/OCert evidence at an epoch boundary; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Header validation and full block validation must not disagree for the same block under the same ledger state.
- Expected Cardano/Intersect impact: Potential High if adversarial but protocol-reachable peer data makes honest nodes prefer a non-canonical or less-secure chain beyond intended security assumptions.
- Fast validation: Fuzz serialized headers and body-hash mismatches while asserting no cached-valid reuse across predecessor contexts.
