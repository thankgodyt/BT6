# Q1967: candidate switching while cleanup is eligible in liftTail

## Question
Can an unprivileged attacker reach liftTail with candidate switching while cleanup is eligible and fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing, then starve a valid competing chain without prohibited flood-style DoS in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/Combinator/Protocol/ChainSel.hs / liftTail
- Entrypoint: Remote peer sends adversarial but protocol-reachable ChainSync headers, BlockFetch bodies, duplicates, and rollbacks through normal node-to-node syncing.
- Attacker controls: fork density, chain fragment ancestry, invalid descendant timing, validation cache pressure, and restart boundary timing.
- Exploit idea: Drive `liftTail` in `Ouroboros.Consensus.HardFork.Combinator.Protocol.ChainSel` through the production entrypoint using candidate switching while cleanup is eligible; verify whether the path can starve a valid competing chain without prohibited flood-style DoS before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: A candidate fragment must not become preferred unless every required predecessor and validation result is consistent.
- Expected Cardano/Intersect impact: Potential High if peer-derived storage, snapshot, replay, or rollback state causes durable use of the wrong ledger state or permanent rejection of a valid chain.
- Fast validation: Create an io-sim scenario with a malicious body-withholding peer and an honest complete-chain peer.
