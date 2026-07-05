### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation via Fake Weight Boosts - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or quorum verification. This stub is wired directly into the production inbound-certificate processing path. An unprivileged peer can therefore inject arbitrary Peras certificates over the object-diffusion mini-protocol; each fake certificate is accepted, stored in the `PerasCertDB`, and used to boost a block's chain-selection weight, potentially causing an honest node to prefer an adversarial chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:** [1](#0-0) 

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

The function accepts a raw `PerasCert blk` and wraps it in `ValidatedPerasCert` without verifying any cryptographic property, without checking that the certificate represents a genuine quorum of committee votes, and without checking any round-number constraints. The `ValidatedPerasCert` wrapper is the type-level proof that a certificate is legitimate; the stub forges that proof for every input.

**Production wiring — inbound certificate handler:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator to `processCerts`. `processCerts` calls this validator on every certificate received from a remote peer: [3](#0-2) 

Because the validator always returns `Right`, every certificate in every inbound batch passes, is timestamped, and is forwarded to `ChainDB.addPerasCertAsync`.

**Chain-selection consequence:**

`chainSelSync` in `ChainSel.hs` processes each accepted certificate: it adds it to the `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block. [4](#0-3) 

Chain selection compares fragments by `wsvTotalWeight = blockNo + weightBoost`: [5](#0-4) 

A fake certificate injects `perasWeight` (default 15) of extra weight onto the adversarial chain per injected certificate, with no upper bound on how many certificates a peer may send.

**Analog mapping to the external report:**

| External report | This finding |
|---|---|
| `setSwapFee` has a per-call limit (`MAXIMUM_SWAP_FEE_PERCENT_CHANGE`) | `validatePerasCert` has a per-certificate check (quorum + crypto) |
| No cooldown between calls → multiple calls bypass the limit | No actual check in the stub → every certificate bypasses the limit |
| Attacker sets fee to any value by calling repeatedly | Attacker boosts any block by any amount by sending many fake certs |
| Manipulation of pool spot price | Manipulation of chain-selection weight |

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can send an unbounded number of crafted `PerasCert` messages, each boosting an arbitrary block on an adversarial fork. Because `perasWeight` (15) is added per certificate and there is no per-round deduplication enforced at the validation layer (the `PerasCertDB` deduplicates by round number, but an attacker can use distinct round numbers), the adversarial chain accumulates weight far exceeding the honest chain. Honest nodes then switch to the adversarial chain, constituting a consensus safety failure: an invalid chain (one whose certificates were never backed by a real quorum) is accepted as canonical.

This matches the **Critical** impact category: bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain selection divergence.

---

### Likelihood Explanation

Any peer that can open an object-diffusion connection can exploit this. No stake, no keys, and no prior knowledge of the network state are required. The attack is mechanically trivial: craft `PerasCert` records with arbitrary `pcCertRound` and `pcCertBoostedBlock` fields and send them in a batch. The only prerequisite is that the target node has Peras enabled; Peras is currently disabled by default but the production code path is fully wired and the stub is the only validator in place.

---

### Recommendation

Replace the stub with a real implementation before Peras is enabled in any deployment:

1. Verify the certificate's cryptographic signature(s) against the committee's public keys.
2. Verify that the certificate encodes a genuine quorum (total stake of signers ≥ `perasQuorumStakeThreshold`).
3. Verify that `pcCertRound` is within the valid window (not expired per `perasCertMaxRounds`, not from the future).
4. Enforce a per-round uniqueness invariant at the validation layer (not only at the DB layer) so that a single round cannot be boosted multiple times via distinct but fake certificates.

The same analysis applies to `validatePerasVote`, which also carries a stub implementation. [6](#0-5) 

---

### Proof of Concept

```
1. Enable Peras on a private testnet node (set rnFeatureFlags to enable Peras).

2. From an adversarial peer, open an object-diffusion connection and send a
   batch of PerasCert messages:
     [ PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }
     | r <- [1..N] ]
   where adversarialBlockPoint is any block on the adversarial fork.

3. processCerts calls (validatePerasCert mkPerasParams) on each certificate.
   The stub returns Right for every one.

4. Each certificate is stored in PerasCertDB under its round number.

5. chainSelSync triggers chainSelectionForBlock for adversarialBlockPoint.

6. weightBoostOfFragment now returns N * perasWeight (= N * 15) for the
   adversarial fragment.

7. preferCandidate compares wsvTotalWeight: the adversarial chain wins and
   the honest node switches to it, accepting an invalid chain as canonical.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-174)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
