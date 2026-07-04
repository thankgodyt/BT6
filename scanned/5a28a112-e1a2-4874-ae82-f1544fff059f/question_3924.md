# Q3924: a header accepted before the body hash is checked in dictPast

## Question
Can an unprivileged attacker reach dictPast with a header accepted before the body hash is checked and header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash, then make a valid block permanently or durably rejected in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/LedgerView.hs / dictPast
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: header fields, slot numbers, issuer keys, VRF proof bytes, KES signature bytes, operational certificates, body hash, and predecessor hash.
- Exploit idea: Drive `dictPast` in `Ouroboros.Consensus.HardFork.Combinator.Protocol.LedgerView` through the production entrypoint using a header accepted before the body hash is checked; verify whether the path can make a valid block permanently or durably rejected before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A block/header accepted by consensus must satisfy the protocol, ledger-view, issuer, slot, and signature assumptions for that exact state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
