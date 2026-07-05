### Title
Unconditional Peras Certificate Acceptance Bypasses All Cryptographic Validation, Enabling Unprivileged Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right` (success) without performing any cryptographic or structural verification. Any unprivileged peer connected via the Peras object-diffusion mini-protocol can inject an arbitrary `PerasCert` naming any block point, which is accepted, stored in the `ChainDB`, and immediately applied as a `PerasWeight 15` boost to the named block during chain selection. This allows a peer with no keys or stake to make an honest node prefer a non-canonical fork over the honest chain.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The only `BlockSupportsPeras` instance in the codebase is the catch-all degenerate instance:

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

There is no Cardano-specific override of this instance anywhere in the repository. Every call to `validatePerasCert` in production code resolves to this stub.

**Production inbound path — `makePerasCertPoolWriterFromChainDB`:**

The production writer for inbound peer certificates calls `validatePerasCert mkPerasParams` directly:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` applies `validateCert` to every cert not already in the DB, and if all pass (which they always do), calls `addCert` for each: [3](#0-2) 

**Chain selection impact — `PerasWeight 15` boost applied unconditionally:**

`mkPerasParams` sets `perasWeight = PerasWeight 15`: [4](#0-3) 

The accepted cert's `vpcCertBoost` is stored in the `PerasWeightSnapshot` and applied during chain selection via `preferAnchoredCandidate`, which computes `wsvTotalWeight = PerasWeight(blockNo) + wsvWeightBoost` and switches to the heavier chain: [5](#0-4) [6](#0-5) 

**Secondary bypass — `validatePerasVote` omits signature verification:**

The same degenerate instance's `validatePerasVote` only checks that the claimed voter ID exists in the stake distribution; it performs no cryptographic signature check on the vote body. An attacker who knows the public stake distribution (which is public on-chain data) can submit votes impersonating any registered voter, accumulate fake quorum, and trigger `forgePerasCert` to produce a fraudulent certificate internally: [7](#0-6) 

---

### Impact Explanation

**Severity: High — Chain selection manipulation by an unprivileged peer.**

An attacker with no stake, no keys, and no privileged access can connect to a node via the Peras object-diffusion mini-protocol and inject a `PerasCert` naming any block point (including a block on a minority fork). The cert is unconditionally accepted and stored. During the next chain selection event, the boosted fork gains `PerasWeight 15` extra weight. Since `wsvTotalWeight` is the primary comparator, a fork that is 15 blocks shorter than the honest chain will be preferred if it carries this fraudulent boost. This directly violates the Peras security assumption that only a quorum of legitimately elected committee members can boost a block.

---

### Likelihood Explanation

**High.** The Peras object-diffusion mini-protocol is a network-facing endpoint reachable by any peer. The attacker needs only to:
1. Connect to a node.
2. Send a well-formed `PerasCert` CBOR message with an arbitrary `pcCertRound` and `pcCertBoostedBlock`.

No stake, no keys, no prior knowledge beyond the target block's point (slot + hash, both public) is required. The `PerasCert` data type is simple and fully serialisable: [8](#0-7) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real verifier that:
1. Checks the certificate's aggregate signature against the claimed committee members' public keys.
2. Verifies that the signers collectively hold stake above the quorum threshold (`perasQuorumStakeThreshold`).
3. Verifies that the boosted block point is a known, valid block on a plausible chain.

Until real committee selection and cryptographic verification are implemented, the Peras cert inbound path (`makePerasCertPoolWriterFromChainDB`) must not be exposed to untrusted peers. The TODO at `https://github.com/tweag/cardano-peras/issues/120` tracks this but does not prevent the stub from being active in production builds.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → Peras ObjectDiffusion mini-protocol
     → makePerasCertPoolWriterFromChainDB.opwAddObjects [craftedCert]
     → processCerts ... (validatePerasCert mkPerasParams) (addPerasCertAsync chainDB)
     → validatePerasCert mkPerasParams craftedCert
         = Right (ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = PerasWeight 15 })
     → ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
     → PerasWeightSnapshot updated: craftedCert.pcCertBoostedBlock += PerasWeight 15
     → preferAnchoredCandidate: fork containing boosted block gains 15 weight units
     → ShouldSwitch if fork is within 15 blocks of honest tip
```

**Crafted cert (CBOR, degenerate instance serialisation):**

```haskell
PerasCert
  { pcCertRound       = PerasRoundNo <any_round>
  , pcCertBoostedBlock = BlockPoint <target_slot> <target_hash>
  }
```

No signature field exists in the degenerate `PerasCert` data type, so no forgery of cryptographic material is required. The cert is structurally complete as-is. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
```haskell
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```
