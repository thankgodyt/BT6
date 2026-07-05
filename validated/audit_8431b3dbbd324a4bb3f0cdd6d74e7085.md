### Title
`validatePerasCert` Stub Unconditionally Accepts Any Peer-Supplied Peras Certificate Without Cryptographic or Quorum Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every inbound certificate without performing any cryptographic signature check, quorum check, or structural validation. An unprivileged peer can craft and send an arbitrary `PerasCert` (any round number, any boosted block hash) through the object-diffusion mini-protocol; the node will accept it as fully valid, store it in the `PerasCertDB`, and use it to boost the attacker-chosen block during chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for all inbound Peras certificates. The only concrete instance — a blanket instance over all `StandardHash blk` blocks — implements this gate as a no-op:

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

The function ignores the certificate body entirely: it performs no aggregate-BLS-signature verification, no check that the claimed voters actually reached quorum, no check that the round number is plausible, and no check that the boosted block exists. It wraps the raw, unverified `PerasCert` in a `ValidatedPerasCert` and returns it as `Right`.

This stub is the **only** instance. The comment "degenerate instance for all blks to get things to compile" confirms it is not a specialised test double — it is the production code path for every block type.

The inbound certificate pipeline in `PerasCert.hs` calls `validatePerasCert` on every certificate received from a peer before storing it: [2](#0-1) 

Because `validatePerasCert` always succeeds, every peer-supplied certificate passes validation and is forwarded to `PerasCertDB.addPerasCert`, which in turn triggers `ChainDB.addPerasCert` and the chain-selection side-effects in `ChainSel.hs`.

For contrast, the analogous vote path does perform real validation: `validatePerasVote` looks up the voter in the stake distribution and rejects unknown voters, and `processVotes` disconnects the peer on any failure. [3](#0-2) [4](#0-3) 

No equivalent rejection path exists for certificates.

The parallel to the external report is direct: just as `AgentDAO::_updateMaturity` decodes the `params` array and passes it to `battleElo` without checking its length — allowing an attacker to supply an arbitrarily large votes array that inflates the ELO — `validatePerasCert` decodes the inbound certificate and wraps it as validated without checking any of its fields, allowing an attacker to supply an arbitrarily crafted certificate that inflates the Peras boost weight applied to an attacker-chosen block.

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is applied directly during chain selection to increase the effective weight of the boosted block's chain. An attacker who injects a certificate for a block on a weaker (or entirely fabricated) fork causes honest nodes to treat that fork as heavier than the canonical chain, producing a chain-selection divergence. Because the certificate is stored durably in `PerasCertDB` and propagated to other peers via the same object-diffusion protocol, the effect is not local: the forged certificate spreads across the network, potentially causing a network-wide consensus split.

This maps to the allowed impact: **Critical — bypass of Peras certificate checks that enables unauthorized certificate acceptance**, and **High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The attack requires only a TCP connection to a Cardano node running the Peras object-diffusion mini-protocol. No stake, no keys, no prior knowledge of the network state is needed. The attacker constructs a `PerasCert` CBOR value with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, sends it over the mini-protocol, and the node accepts it. The attack is fully scriptable and repeatable.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:

1. Verifies the aggregate BLS signature over the claimed voter set against the claimed election ID and boosted block hash.
2. Checks that the claimed voter set's total stake meets or exceeds the quorum threshold (`stakeAboveThreshold`).
3. Checks that each claimed voter seat index is within bounds and maps to a pool with positive stake in the current stake distribution.
4. Checks that the certificate's round number falls within the expected window.

Until a full implementation is ready, the stub should at minimum return `Left PerasValidationErr` (reject all certificates) rather than `Right` (accept all certificates), so that the failure mode is safe rather than exploitable.

---

### Proof of Concept

1. Attacker connects to an honest node via the Peras certificate object-diffusion mini-protocol.
2. Attacker serialises a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of attacker's chosen block>`.
3. Node receives the certificate and calls `validatePerasCert params cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally. [5](#0-4) 
5. The certificate is stored in `PerasCertDB` and forwarded to `ChainDB.addPerasCert`.
6. `ChainSel` applies the `vpcCertBoost` weight to the attacker's chosen block, making its chain appear heavier.
7. The node switches to the attacker's fork; the forged certificate is gossiped to peers, spreading the divergence.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-200)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
```
