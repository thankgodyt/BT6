# Q3148: VRF KES OCert evidence at an epoch boundary in pHeaderBlock

## Question
Can an unprivileged attacker reach pHeaderBlock with VRF/KES/OCert evidence at an epoch boundary and block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Protocol/Abstract.hs / pHeaderBlock
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags.
- Exploit idea: Drive `pHeaderBlock` in `Ouroboros.Consensus.Shelley.Protocol.Abstract` through the production entrypoint using VRF/KES/OCert evidence at an epoch boundary; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Header validation and full block validation must not disagree for the same block under the same ledger state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
