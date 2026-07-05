### Title
`PerasCertDB` Uses `PerasRoundNo` as Sole Cardinality Key, Allowing Unauthenticated Certificate Injection to Permanently Block Legitimate Peras Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The `PerasCertDB` deduplicates certificates using only `PerasRoundNo` as the key (first-write-wins). Certificate validation is explicitly marked as a TODO and is not implemented. An unprivileged peer can therefore inject a crafted certificate for any round before the legitimate one arrives. Once stored, the legitimate certificate is permanently rejected as `PerasCertAlreadyInDB`, its chain-selection boost is never applied, and the node may prefer a non-canonical chain.

---

### Finding Description

`implAddCert` in `PerasCertDB/Impl.hs` performs the following deduplication check:

```haskell
let roundNo = getPerasCertRound cert
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
``` [1](#0-0) 

The `pcdsCertIds` field is a `Set PerasRoundNo` — the round number alone is the cardinality key. [2](#0-1) 

The boosted block hash (`pcCertBoostedBlock`) and any cryptographic proof are **not** part of the deduplication key. The `ValidatedPerasCert` type carries no enforced cryptographic invariant at this layer: [3](#0-2) 

The validation TODO is explicit and unresolved:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ...
``` [4](#0-3) 

When `PerasCertAlreadyInDB` is returned, `chainSelSync` exits early via `idExitEarly`, so the honest certificate's Peras weight boost is **never applied** to chain selection: [5](#0-4) 

The weight snapshot derived from `pcdsCertsByTicket` directly feeds `preferAnchoredCandidate` in chain selection: [6](#0-5) [7](#0-6) 

The `PerasCertDB` API is designed to accept certificates from external peers (the `addCert` field is exposed via `ChainDB`): [8](#0-7) 

The state-machine test explicitly avoids equivocating certificates as a precondition, confirming the implementation does not handle them: [9](#0-8) 

---

### Impact Explanation

An adversary peer injects a crafted `ValidatedPerasCert` for round N boosting an adversarial block A before the legitimate certificate (boosting honest block B) propagates. The adversarial certificate is stored; the legitimate one is permanently rejected as `PerasCertAlreadyInDB`. The `getWeightSnapshot` then returns a `PerasWeightSnapshot` that boosts block A instead of block B. `preferAnchoredCandidate` uses this snapshot in chain selection, potentially causing the node to prefer the adversarial chain over the honest chain. This is a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain** beyond the intended Peras security assumptions.

---

### Likelihood Explanation

**Medium.** The attack requires only that the adversary send a network message containing a crafted certificate for the target round before the legitimate certificate arrives. No stake, keys, or quorum are required because validation is not implemented. The attack window is the propagation delay of the legitimate certificate. The adversary must be a connected peer, which is a normal network condition. The `PerasCertDB` is volatile (in-memory), so the attack must be repeated after each node restart, but within a session the effect is permanent.

---

### Recommendation

1. **Implement certificate validation before storage**: verify the quorum proof, BLS aggregate signature, and that the boosted block exists and is on a valid chain, before calling `addCert`. This is already tracked as an open issue referenced in the TODO.
2. **Include the boosted block hash in the deduplication key**: use `(PerasRoundNo, HeaderHash blk)` rather than `PerasRoundNo` alone, so that an equivocating certificate for the same round but a different block is detected and rejected rather than silently blocking the legitimate one.
3. **Reject equivocating certificates explicitly**: if a certificate for round N already exists and a new certificate for round N boosts a different block, treat this as an equivocation error rather than a silent duplicate.

---

### Proof of Concept

1. Connect to a target node as an unprivileged peer.
2. Observe that round N is in progress (or about to complete).
3. Before the legitimate quorum certificate for round N propagates, send a crafted `ChainSelAddPerasCert` message containing a `ValidatedPerasCert` with `pcCertRound = N` and `pcCertBoostedBlock = adversarialBlockPoint`.
4. `implAddCert` checks `Set.member N pcdsCertIds` → False → stores the adversarial certificate; `pcdsCertIds` now contains N.
5. The legitimate certificate for round N arrives. `implAddCert` checks `Set.member N pcdsCertIds` → True → returns `PerasCertAlreadyInDB`.
6. `chainSelSync` calls `idExitEarly (PerasCertProcessed PerasCertAlreadyInDB)` — the honest block's Peras weight boost is never applied.
7. `getWeightSnapshot` returns weights boosting the adversarial block. `preferAnchoredCandidate` may now select the adversarial chain over the honest chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L50-52)
```haskell
data PerasCertDbState blk = PerasCertDbState
  { pcdsCertIds :: !(Set PerasRoundNo)
  -- ^ The round numbers of all certificates currently in the db.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-179)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L495-502)
```haskell
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-635)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L36-48)
```haskell
data PerasCertDB m blk = PerasCertDB
  { addCert ::
      WithArrivalTime (ValidatedPerasCert blk) ->
      STM m (m AddPerasCertResult)
  -- ^ Add a Peras certificate to the database. The STM transaction adds the
  -- certificate to the in-memory index, and the resulting 'm' action performs
  -- tracing and might perform side-effects in implementations with on-disk
  -- storage.
  -- The 'AddPerasCertResult' indicates whether the certificate was actually
  -- added, or if it was already present.
  --
  -- NOTE: Use the @join . atomically@ pattern to run both the transaction
  -- and the side-effects in sequence.
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasCertDB/StateMachine.hs (L128-143)
```haskell
  precondition (Model model) = \case
    OpenDB -> not model.open
    action ->
      model.open && case action of
        -- Do not add equivocating certificates.
        AddCert cert -> all p model.certs
         where
          -- We should reject equivocating certificates, that is, certificates
          -- for the same round but boosting different blocks.
          -- So we should enforce: round = round' => boostedBlock = boostedBlock'
          p cert' =
            getPerasCertRound cert /= getPerasCertRound cert'
              || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
        GetWeightSnapshot -> True
        GetLatestCertSeen -> True
        GarbageCollect _slotNo -> True
```
