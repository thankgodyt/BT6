### Title
Stub `validatePerasCert` Allows Any Peer to Permanently Pre-Occupy a Peras Round's Certificate Slot, Corrupting Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The Peras certificate diffusion layer uses `PerasRoundNo` as a deterministic, globally-predictable object ID for certificates (one cert per round). The `validatePerasCert` implementation is a stub that unconditionally accepts every inbound certificate. Because the `PerasCertDB` stores the **first** cert received for a given round and silently drops all subsequent ones, any unprivileged peer can permanently pre-occupy a round's certificate slot with a crafted cert that boosts an attacker-controlled block. The legitimate cert for that round is then permanently blocked, and the node's chain-selection weight snapshot is corrupted to favour a non-canonical fork.

---

### Finding Description

**Deterministic, predictable object ID.** A Peras certificate is identified solely by its `PerasRoundNo`. Round numbers are globally known and advance on a fixed schedule, so any peer can predict which round number will be needed next.

**Stub validation accepts everything.** The only production instance of `BlockSupportsPeras` is a universal stub:

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

This means `validatePerasCert` returns `Right` for **any** `PerasCert`, regardless of its `pcCertBoostedBlock` or any cryptographic content.

**`processCerts` uses this stub as its sole gate.** The inbound certificate processing pipeline in `PerasCert.hs` filters out certs already in the DB, then calls `validateCert` (bound to the stub above) on the remainder. If all pass, they are added:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

**First writer wins; subsequent certs for the same round are permanently dropped.** `implAddCert` in `PerasCertDB.Impl` checks whether the round is already present and, if so, returns `PerasCertAlreadyInDB` without updating the stored cert:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
``` [3](#0-2) 

There is no mechanism to replace a stored cert for a round with a better one. The slot is permanently occupied.

**The `opwObjectId` for certs is `getPerasCertRound`**, confirming that the round number is the sole deduplication key used by the ObjectDiffusion layer: [4](#0-3) 

---

### Impact Explanation

A Peras certificate stored in the DB is used to compute the `PerasWeightSnapshot`, which provides chain-selection weight boosts to the block named in `pcCertBoostedBlock`. If an attacker pre-occupies round R with a cert boosting an attacker-controlled block B', the honest node will:

1. Permanently drop the legitimate cert for round R (boosting the canonical block B).
2. Apply the Peras weight boost to B' instead of B.
3. Prefer the fork containing B' over the canonical chain, diverging from honest consensus.

This is a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended security assumptions of the Peras protocol. [5](#0-4) 

---

### Likelihood Explanation

- **Entry path is fully open**: any peer that establishes an ObjectDiffusion connection can send arbitrary `PerasCert` objects. No stake, key material, or privilege is required.
- **Round numbers are predictable**: they advance on a fixed schedule known to all participants, so the attacker can craft a cert for the next round before the legitimate cert is produced.
- **No cryptographic barrier**: `validatePerasCert` is a stub that accepts every cert unconditionally. The attacker does not need to forge any signature or satisfy any committee membership proof.
- **Permanent effect**: once a cert for round R is stored, it cannot be replaced. The damage persists for the lifetime of the node's DB state.

---

### Recommendation

1. **Implement real `validatePerasCert` logic** before the ObjectDiffusion cert inbound path is enabled in production. At minimum, validate committee membership, BLS aggregate signature, and that `pcCertBoostedBlock` refers to a known block on a plausible chain.
2. **Bind the cert ID to its content**: consider using a content-addressed ID (e.g., a hash of the full cert) rather than the bare `PerasRoundNo`, so that a cert for round R with the wrong boosted block cannot occupy the slot intended for the legitimate cert.
3. **Allow replacement of a stored cert** if a later cert for the same round has strictly higher validity evidence (e.g., more signers), rather than silently dropping it.

---

### Proof of Concept

```
1. Attacker node A connects to honest node H via the ObjectDiffusion miniprotocol.

2. A observes that Peras round R is about to begin (round numbers are public).

3. A crafts:
     PerasCert { pcCertRound = R, pcCertBoostedBlock = attackerBlock }
   where `attackerBlock` is a point on a fork A controls.

4. A sends this cert to H via ObjectDiffusion before any honest cert for round R
   arrives.

5. H calls processCerts:
   - alreadyInDb does NOT contain R  =>  cert is not filtered out
   - validatePerasCert (stub) returns Right  =>  cert passes validation
   - implAddCert stores the cert: pcdsCertIds now contains R,
     pcCertBoostedBlock = attackerBlock

6. The legitimate cert for round R (boosting the canonical block) arrives later.
   implAddCert sees Set.member R pcdsCertIds => returns PerasCertAlreadyInDB.
   The legitimate cert is permanently dropped.

7. H's PerasWeightSnapshot now boosts attackerBlock.
   Chain selection on H prefers the fork containing attackerBlock over the
   canonical chain, causing H to diverge from honest consensus.
``` [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
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
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```
