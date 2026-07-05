### Title
Unconditional Peras Certificate Acceptance Bypasses All Vote-Quorum Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, accepting it without checking votes, quorum stake, round validity, or any cryptographic proof. Any unprivileged peer can send a crafted `PerasCert` that names an arbitrary block as its boosted target; the certificate is stored in the `PerasCertDB`/`ChainDB` and immediately influences chain selection with a `perasWeight = 15` boost.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a received Peras certificate before it is persisted and used in chain selection. The sole concrete instance (used for all block types) is a stub:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

This stub is wired directly into both production pool-writer constructors:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` — the inbound handler called for every batch of peer-supplied certificates — passes each certificate through `validateCert` and adds it to the database only when the result is `Right`. Because `validatePerasCert` is always `Right`, every certificate passes:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

The `makePerasCertPoolWriterFromChainDB` path feeds directly into `ChainDB.addPerasCertAsync`, which triggers chain selection side-effects. [5](#0-4) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification checks.**

A `ValidatedPerasCert` carries a `vpcCertBoost` field (default `perasWeight = 15`) that is added to the chain-selection weight of the boosted block. [6](#0-5) 

An attacker who injects a forged certificate for a minority or adversarial chain causes honest nodes to prefer that chain over the canonical one, constituting a chain-selection manipulation without any stake majority or key compromise. No votes, no quorum, no cryptographic proof of any kind is required.

---

### Likelihood Explanation

The object diffusion mini-protocol is a standard node-to-node protocol reachable by any peer that can establish a connection. The attacker only needs to:
1. Connect to a target node.
2. Advertise a `PerasRoundNo` not yet in the node's `PerasCertDB`.
3. Respond with a crafted `PerasCert` naming any `Point blk` as the boosted block.

No privileged access, no key material, and no stake is required. The `processCerts` deduplication check (`Set.member roundNo alreadyInDb`) only prevents re-injection of the same round number, not injection of a fresh forged certificate for a new round. [7](#0-6) 

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the certificate contains a valid set of votes whose aggregate stake exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin` (analogous to the fix recommended in the external report: reject when the vote count is zero).
2. Verifies each vote's cryptographic signature against the claimed voter's key.
3. Verifies the voter was a member of the committee for the claimed round (i.e., appears in the stake distribution with non-zero stake).
4. Verifies the boosted block's slot satisfies `perasBlockMinSlots`.

The existing `stakeAboveThreshold` helper and `votesReachQuorum` smart constructor already enforce the zero-vote guard (`[] -> Nothing`) and the stake threshold check; `validatePerasCert` must invoke equivalent logic on the votes embedded in the certificate. [8](#0-7) 

---

### Proof of Concept

**Setup**: A private testnet with one honest node running the Peras-enabled consensus layer.

**Steps**:

1. The attacker connects to the honest node via the node-to-node object diffusion mini-protocol for Peras certificates.
2. The attacker advertises `PerasRoundNo 42` (a round not yet in the node's DB).
3. When the node requests the certificate, the attacker replies with:
   ```
   PerasCert { pcCertRound = 42
             , pcCertBoostedBlock = <point of attacker's minority-chain tip> }
   ```
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns:
   ```
   Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })
   ```
   — no votes, no quorum check, no signature check.
5. The certificate is stored via `ChainDB.addPerasCertAsync`.
6. Chain selection now adds 15 to the weight of the attacker's block, potentially making the honest node switch to the attacker's chain.

The root cause is structurally identical to the DAO bug: just as `0 >= 0` trivially satisfies the quorum predicate when no members exist, `Right (...)` trivially satisfies the validation predicate regardless of the certificate's content. [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L247-271)
```haskell
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-176)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
```
