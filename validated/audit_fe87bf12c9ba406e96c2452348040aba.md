### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Artificial Chain-Weight Inflation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives. Because this function is the sole gate between the object-diffusion mini-protocol and the `PerasCertDB` / `PerasWeightSnapshot`, any unprivileged peer can inject an arbitrary number of crafted `PerasCert` values—each targeting a different round number but boosting the same block—causing that block's chain-selection weight to be multiplied without bound. This is the direct analog of the DYAD double-counting flaw: just as the same WETH vault was registered in both `KeroseneManager` and `VaultLicenser` so it could be counted twice in the collateral ratio, here the same block can be "registered" in the weight snapshot via multiple fake certificates, each adding a full `perasWeight` boost, inflating the apparent weight of a chosen chain beyond what honest stake can produce.

---

### Finding Description

**Root cause — stub validation** [1](#0-0) 

The universal instance (applied to every `StandardHash blk`) implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No cryptographic check, no committee membership check, no round-range check, no boosted-block existence check. Every certificate from every peer is accepted.

**Entry path — object diffusion writer**

`processCerts` in the production cert-pool writer reads the current DB state once in an STM transaction, then calls `validatePerasCert` outside that transaction, and finally calls `addCert` for each cert that passed: [2](#0-1) 

Both production writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass `validatePerasCert mkPerasParams` as the validator: [3](#0-2) [4](#0-3) 

**Deduplication is per-round, not per-block**

`implAddCert` deduplicates by `roundNo` only: [5](#0-4) 

A peer can therefore send N certificates, each with a distinct `pcCertRound`, all with the same `pcCertBoostedBlock`. Each passes the stub validator, each is stored, and each contributes a full `perasWeight` boost to the target block.

**Weight accumulation is additive and unbounded**

`addToPerasWeightSnapshot` uses `Map.insertWith (<>)`, so duplicate points accumulate weight: [6](#0-5) 

The glossary explicitly notes this design: *"Note that the same point can be boosted multiple times."* The security assumption is that each boost is backed by a legitimately validated certificate. With the stub, that assumption is broken.

**Chain selection uses the inflated snapshot**

`compareAnchoredFragments` and `weightedSelectView` use the `PerasWeightSnapshot` directly to prefer the heavier fragment: [7](#0-6) [8](#0-7) 

A block boosted N times by fake certificates has total weight `blockNo + N × perasWeight`, which can exceed the weight of any honest chain of reasonable length.

---

### Impact Explanation

An unprivileged peer connected via the object-diffusion mini-protocol can:

1. Craft N `PerasCert` values, each with a distinct `pcCertRound` and the same `pcCertBoostedBlock` pointing to any block in the VolatileDB.
2. All N certs pass `validatePerasCert` (stub always returns `Right`).
3. All N certs are stored in `PerasCertDB`; the `PerasWeightSnapshot` accumulates N × `perasWeight` for the target block.
4. Chain selection now prefers any chain containing that block, regardless of honest chain length.
5. The victim node switches to a non-canonical or adversarially chosen chain, constituting a consensus safety failure.

This matches two allowed impact categories:
- **Critical**: Bypass of Peras certificate checks enabling unauthorized certificate acceptance.
- **High**: Chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

The object-diffusion mini-protocol is a standard node-to-node protocol; any peer the node connects to can send `PerasCert` objects. No special privileges, keys, or stake are required. The attacker only needs to be a connected peer and send a batch of crafted certificates with distinct round numbers. The stub is in the universal instance applied to all block types in production, not gated behind a feature flag.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
- The certificate's round number falls within the valid range for the current epoch.
- The boosted block exists and is within the volatile window.
- The certificate carries a valid aggregate signature from a quorum of the elected committee for that round (matching the `Committee.Class` interface already defined in the codebase).
- The `vpcCertBoost` is derived from protocol parameters, not from the certificate itself.

Until real validation is in place, the object-diffusion cert writer should refuse to accept any externally supplied certificate (i.e., keep the DB empty or gate ingestion behind a feature flag), so that the only certificates that influence chain selection are those forged locally from validated votes.

---

### Proof of Concept

```
-- Attacker sends N crafted certs, all boosting block B at different rounds
let fakeCerts = [ PerasCert { pcCertRound    = PerasRoundNo r
                             , pcCertBoostedBlock = blockPointB }
                | r <- [1..N] ]

-- processCerts calls validatePerasCert on each:
--   validatePerasCert params cert = Right (ValidatedPerasCert cert perasWeight)
-- => all N certs pass, all stored in PerasCertDB

-- implGetWeightSnapshot builds:
--   mkPerasWeightSnapshot [(blockPointB, perasWeight), ..., (blockPointB, perasWeight)]
--   = PerasWeightSnapshot { blockPointB -> N * perasWeight }

-- compareAnchoredFragments now sees:
--   totalWeight(chain containing B) = blockNo(B) + N * perasWeight
-- which exceeds any honest chain of length < N * perasWeight
-- => victim node switches to attacker's chosen chain
``` [9](#0-8) [10](#0-9) [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L125-132)
```haskell
addToPerasWeightSnapshot ::
  StandardHash blk =>
  Point blk ->
  PerasWeight ->
  PerasWeightSnapshot blk ->
  PerasWeightSnapshot blk
addToPerasWeightSnapshot pt weight =
  PerasWeightSnapshot . Map.insertWith (<>) pt weight . getPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L143-149)
```haskell
  | otherwise =
      case AF.intersect frag1 frag2 of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          compare
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```
