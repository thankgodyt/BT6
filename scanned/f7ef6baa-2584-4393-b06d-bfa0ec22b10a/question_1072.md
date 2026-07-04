# Q1072: node to node data decoded in verifyBlockIntegrity

## Question
Can an unprivileged attacker reach verifyBlockIntegrity with node-to-node data decoded with a mismatched era tag and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Integrity.hs / verifyBlockIntegrity
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `verifyBlockIntegrity` in `Ouroboros.Consensus.Shelley.Ledger.Integrity` through the production entrypoint using node-to-node data decoded with a mismatched era tag; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential Critical if a crafted boundary block causes honest nodes to disagree on block validity or accept invalid state.
- Fast validation: Replay the same multi-era chain live and from persisted storage and compare hard-fork summary, selected tip, and ledger state hash.
