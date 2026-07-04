# Q95: old era chain selection data influencing new era preference in activeSlotsCoef

## Question
Can an unprivileged attacker reach activeSlotsCoeffDecCBOR with old-era chain selection data influencing new-era preference and transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/Ledger/Query/LegacyShelleyGenesis.hs / activeSlotsCoeffDecCBOR
- Entrypoint: Remote peer or normal block producer delivers blocks, headers, queries, or encoded messages around an era boundary through supported node protocols.
- Attacker controls: transition ledger state, protocol parameter translation, forecast window, current-era tip, and historical summary reconstruction inputs.
- Exploit idea: Drive `activeSlotsCoeffDecCBOR` in `Ouroboros.Consensus.Shelley.Ledger.Query.LegacyShelleyGenesis` through the production entrypoint using old-era chain selection data influencing new-era preference; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Forecast windows and ledger views must not allow stale pre-transition context to validate post-transition blocks.
- Expected Cardano/Intersect impact: Potential High if replay or rollback across an era boundary makes honest nodes select different valid-chain tips.
- Fast validation: Fuzz node-to-node/node-to-client version tags and era indexes and assert mismatched payloads are rejected before validation.
