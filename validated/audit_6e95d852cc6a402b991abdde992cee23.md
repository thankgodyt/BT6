### Title
Unconditional `validatePerasCert` Stub Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection Weight - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a `validatePerasCert` implementation that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. Any unprivileged peer can therefore inject a crafted `PerasCert` targeting any block in the volatile DB, have it accepted as "validated," and cause the receiving node to re-run chain selection with an artificially inflated weight for an adversarial chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is stored and used to boost chain weight. The repository ships a single universal instance for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This stub is the live implementation wired into both inbound certificate processing paths. `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` both pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          ...
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate received from a remote peer. Because `validatePerasCert` always returns `Right`, every certificate passes: [3](#0-2) 

Once accepted, the certificate is stored in the `PerasCertDB` and its boost weight is incorporated into the `PerasWeightSnapshot`. Chain selection then uses `wsvTotalWeight` — the sum of `BlockNo` and `wsvWeightBoost` — to compare candidate chains:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

`chainSelSync` then re-triggers chain selection for the boosted block: [5](#0-4) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

An unprivileged peer can craft a `PerasCert` naming any block in the receiving node's volatile DB (i.e., within the last `k` blocks). Because `validatePerasCert` never rejects anything, the certificate is stored and its `perasWeight` boost is added to that block's chain weight. If the boosted block is on a minority or adversarial fork, the honest node may now compute that fork as heavier than its current selection and switch to it — a consensus safety failure. No cryptographic key material, committee membership proof, VRF output, or quorum evidence is required from the attacker.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a public, unauthenticated peer-to-peer channel. Any node that connects to the victim and speaks the Peras certificate sub-protocol can send an arbitrary `PerasCert` message. The only existing guard discards certificates whose boosted block is older than the immutable tip; certificates targeting any block in the volatile window are processed unconditionally. No special privileges, leaked keys, or stake are required.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed committee members.
2. Each committee member's VRF proof establishing their eligibility for the round.
3. That the total stake of the committee members exceeds the quorum threshold.

Until the full cryptographic plumbing is in place, the inbound certificate processing path (`processCerts`) should reject all externally received certificates rather than accepting them unconditionally, to prevent the stub from being exploited in any deployed or testnet environment.

---

### Proof of Concept

```
Attacker node A connects to honest node H.
A sends a PerasCert message:
  { pcCertRound    = <any round number not yet in H's DB>
  , pcCertBoostedBlock = <Point of a block on A's adversarial fork> }

H's processCerts calls validatePerasCert mkPerasParams cert
  => always returns Right (ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams })

H stores the cert; PerasCertDB fingerprint increments.
H's chainSelSync fires for the boosted block:
  wsvTotalWeight(adversarial fork) = blockNo + perasWeight  -- now heavier
  wsvTotalWeight(honest chain)     = blockNo               -- no boost

preferCandidate returns ShouldSwitch => H switches to A's adversarial fork.
```

No cryptographic material is needed. The attack requires only a valid TCP connection and knowledge of a block hash in H's volatile DB (obtainable via the ChainSync mini-protocol).

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
