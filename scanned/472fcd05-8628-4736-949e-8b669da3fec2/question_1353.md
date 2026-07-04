# Q1353: protocol state updates before late validation failure in Ouroboros Consensus P

## Question
Can an unprivileged attacker reach Ouroboros.Consensus.Protocol.PBFT.Crypto with protocol-state updates before late validation failure and block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags, then make replay after restart differ from live validation in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Protocol/PBFT/Crypto.hs / Ouroboros.Consensus.Protocol.PBFT.Crypto
- Entrypoint: Remote peer sends crafted headers/blocks, or a normal slot leader produces an edge-case block that honest nodes validate through the production consensus path.
- Attacker controls: block header/body pairings, ledger-view timing, protocol state transition inputs, certificate counters, and era-specific validation tags.
- Exploit idea: Drive `Ouroboros.Consensus.Protocol.PBFT.Crypto` in `Ouroboros.Consensus.Protocol.PBFT.Crypto` through the production entrypoint using protocol-state updates before late validation failure; verify whether the path can make replay after restart differ from live validation before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Header validation and full block validation must not disagree for the same block under the same ledger state.
- Expected Cardano/Intersect impact: Potential Critical if the path lets a crafted block/header or protocol-reachable input make an honest node accept an invalid block, invalid ledger state, or divergent irreversible chain.
- Fast validation: Construct a validation property that mutates controlled header fields and compares header validation, body validation, and ledger application.
