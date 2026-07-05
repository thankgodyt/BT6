### Title
Valid Peras Certificates Silently Discarded When Batch Contains Any Invalid Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

`processCerts` in the Peras certificate ObjectDiffusion inbound handler rejects the **entire batch** of certificates when any single certificate fails validation, silently discarding all valid certificates in the same batch. An unprivileged peer can exploit this by sending one crafted invalid certificate mixed with legitimate valid certificates, causing the valid certificates to be permanently dropped from that delivery. Because Peras certificates directly drive the `WeightedSelectView` used in chain selection, a node that is systematically denied valid certificates will undercount the weight boost of the canonical chain and may fail to switch to it.

---

### Finding Description

`processCerts` uses `partitionEithers` to separate valid from invalid certificates, but the error branch discards the valid partition entirely:

```haskell
-- File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/
--        MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs, lines 168–185

case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    (errs, _) ->                          -- ← valid certs in `_` are thrown away
      throw (PerasCertValidationError errs)
```

The wildcard `_` in the error branch is the valid-certificate list produced by `partitionEithers`. It is never passed to `addCert`; it is silently dropped. The same structural defect exists verbatim in `processVotes`:

```haskell
-- File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/
--        MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs, lines 184–201

    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

The thrown `PerasCertInboundException` / `PerasVoteInboundException` types are **not registered** in `consensusRethrowPolicy`. The comment in that file explicitly states "The list below should contain an entry for every type declared as an instance of `Exception` within ouroboros-consensus," yet neither `PerasCertInboundException` nor `PerasVoteInboundException` appears there. The default fallback policy (disconnect + reconnect after ~10–20 s) therefore applies, meaning the peer is disconnected and the valid certificates from the batch are permanently lost for that delivery window.

---

### Impact Explanation

Peras certificates are the mechanism by which blocks receive a **weight boost** in chain selection. From the `WeightedSelectView` implementation:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs
-- lines 63–68
instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight   -- total weight = block number + weight boost
      , compare `on` wsvTiebreaker
      ]
```

A node that is denied valid certificates for a round will compute a lower `wsvTotalWeight` for the boosted chain fragment. If the weight difference is large enough, the node will fail to switch to the canonical (boosted) chain, or will prefer a less-secure fork. This is a chain-selection bug triggered by a miniprotocol flaw: an unprivileged peer can cause an honest node to undercount the weight of the canonical chain by poisoning every certificate batch it delivers.

The impact matches: **Medium — public node miniprotocol flaw that materially weakens certificate authorization**, specifically the Peras certificate diffusion miniprotocol (`ObjectDiffusion`).

---

### Likelihood Explanation

The attack requires no special privileges. Any peer that participates in the Peras certificate ObjectDiffusion miniprotocol can send a batch containing one syntactically or cryptographically invalid certificate alongside valid ones. The `processCerts` function will validate all certificates in the batch, find the one invalid entry, and discard the entire batch including the valid certificates. The attacker does not need to know the content of the valid certificates in advance; it suffices to append a single self-crafted invalid certificate to any batch. If the attacker controls a sufficient fraction of the victim's peers, it can prevent the victim from ever accumulating valid certificates for a given round, persistently suppressing the weight boost of the canonical chain.

---

### Recommendation

Replace the all-or-nothing batch rejection with per-certificate handling: add valid certificates to the database and disconnect the peer only for the invalid ones (or report all errors while still persisting the valid subset):

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb =
        filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, validatedCerts) -> do
      -- Persist the valid subset before disconnecting
      mapM_ (addCert . WithArrivalTime now) validatedCerts
      throw (PerasCertValidationError errs)
```

Apply the same fix to `processVotes`. Additionally, register `PerasCertInboundException` and `PerasVoteInboundException` in `consensusRethrowPolicy` (mapping them to `theyBuggyOrEvil`) so that the disconnect behaviour is explicit and auditable rather than relying on the undocumented default fallback.

---

### Proof of Concept

1. Attacker connects to a victim node and participates in the Peras certificate ObjectDiffusion miniprotocol.
2. The attacker observes (or guesses) that the honest network is about to diffuse a batch of valid certificates for round `R` that boost block `B` on the canonical chain.
3. The attacker constructs a batch: `[validCert_R, invalidCert_R']` where `invalidCert_R'` has a malformed signature or an out-of-range round number.
4. The attacker sends this batch via `opwAddObjects` (the `ObjectPoolWriter` entry point wired to `processCerts`).
5. `processCerts` calls `partitionEithers (validateCert <$> certsNotAlreadyInDb)`, producing `([err], [validatedCert_R])`.
6. The error branch fires: `throw (PerasCertValidationError [err])`. `validatedCert_R` is never passed to `addCert`.
7. The peer is disconnected. The victim node has not stored `validCert_R`.
8. If the attacker repeats this from all peers it controls before any honest peer delivers the certificate alone, the victim never accumulates the weight boost for block `B`.
9. Chain selection on the victim computes `wsvTotalWeight` for the canonical chain without the boost, potentially causing it to prefer a shorter or adversarially-controlled fork. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
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
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/RethrowPolicy.hs (L35-46)
```haskell
-- Exception raised during interaction with the peer
--
-- The list below should contain an entry for every type declared as an
-- instance of 'Exception' within ouroboros-consensus.
--
-- If a particular exception is not handled by any policy, a default
-- kicks in, which currently means logging the exception and disconnecting
-- from the peer (in both directions), but allowing a reconnect within a saall
-- delay (10-20s). This is fine for exceptions that only affect that peer.  It
-- is however essential that we handle exceptions here that /must/ shut down the
-- node (mainly storage layer errors).
--
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-68)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-444)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
```
