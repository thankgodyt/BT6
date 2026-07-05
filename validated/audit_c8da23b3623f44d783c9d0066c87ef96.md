### Title
Placeholder Peras Certificate Validation Allows Malicious Peer to Inject Arbitrary Certificates and Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The Peras certificate ingest path in `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` passes a placeholder validation function — `validatePerasCert mkPerasParams` — to `processCerts` instead of performing real committee-based cryptographic verification. Simultaneously, `implAddCert` in `PerasCertDB/Impl.hs` explicitly defers its own "non-trivial validation logic" via a TODO. An unprivileged peer connected via the object diffusion mini-protocol can send crafted `PerasCert` objects that pass the placeholder check, get stored in the `PerasCertDB`, and then influence Peras chain selection by boosting an attacker-chosen block.

---

### Finding Description

**Root cause — placeholder validator in the ingest writer:**

In `makePerasCertPoolWriterFromChainDB` (the production path used by the `ChainDB`):

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [1](#0-0) 

The same placeholder appears in `makePerasCertPoolWriterFromCertDB`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

The comment "TODO replace when actual plumbing is in place" explicitly acknowledges that the real validation — which must use the ledger-derived voting committee, verify the aggregate BLS/VRF signature over the election ID and candidate block, and confirm quorum — is **not yet wired in**. `mkPerasParams` is a hardcoded default parameter set, not the live committee snapshot derived from the current ledger state.

**Root cause — missing DB-level validation:**

Even after `processCerts` stamps a cert as `ValidatedPerasCert`, `implAddCert` in `PerasCertDB/Impl.hs` carries an explicit deferral:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
``` [3](#0-2) 

The current body of `implAddCert` only checks for a duplicate round number and then unconditionally inserts the certificate: [4](#0-3) 

**End-to-end exploit path:**

1. A malicious peer connects via the object diffusion mini-protocol.
2. It sends a batch of `PerasCert` objects whose round numbers are not yet in the local DB.
3. `processCerts` filters out already-known rounds, then calls `validatePerasCert mkPerasParams` on each remaining cert. Because this function uses hardcoded parameters and does not verify the aggregate vote signature against the actual committee, a crafted cert passes.
4. Each passing cert is wrapped in `WithArrivalTime` and handed to `addCert` → `implAddCert`, which inserts it without further checks.
5. The injected cert is now returned by `getWeightSnapshot` / `getLatestCertSeen`, directly feeding the Peras chain-selection weight computation and the cert-inclusion logic for the next block the node forges. [5](#0-4) 

---

### Impact Explanation

**Critical — bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

A Peras certificate encodes which block won a voting round and carries a boost weight in chain selection. By injecting a certificate for an attacker-chosen block and round, an adversary can:

- Cause the victim node to assign Peras boost weight to a non-canonical or adversarial block, making it preferred over the honest chain tip.
- Have the victim node include the forged certificate in the next block it forges, propagating the invalid certificate to the rest of the network.

This directly satisfies the "Critical" criterion: bypass of Peras voting/certificate checks that enables unauthorized certificate acceptance, and the "High" criterion: chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

**High.** The entry point is any peer reachable via the object diffusion mini-protocol — no special privileges, no key material, no stake required. The placeholder validation is present in both the `PerasCertDB`-direct path and the production `ChainDB` path. The TODO comments confirm the gap is known and unresolved. Any node running with Peras enabled and connected to the public network is exposed.

---

### Recommendation

1. **Replace the placeholder immediately.** `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` must supply a `validateCert` function that:
   - Retrieves the current voting committee from the ledger state at the certificate's round.
   - Calls `verifyCert` on the committee-specific `VotingCommittee` instance (e.g., `implVerifyCert` for `EveryoneVotes` or `WFALS`) to verify the aggregate signature and voter eligibility.
   - Confirms the certificate's boosted block exists on a known chain.

2. **Implement the deferred validation in `implAddCert`.** The referenced issue (`tweag/cardano-peras#120`) should be resolved before Peras is enabled on any network where peers are not fully trusted.

3. **Gate Peras cert acceptance on ledger-view availability.** If the ledger view for the certificate's round is not yet available, the certificate should be buffered or rejected rather than accepted with a stub validator.

---

### Proof of Concept

**Deterministic reasoning (no live network required):**

```
Peer sends: PerasCert { round = R, boostedBlock = B_adversarial, aggSig = <anything> }

processCerts:
  alreadyInDb = {} (round R not yet seen)
  certsNotAlreadyInDb = [cert]
  validateCert cert
    = validatePerasCert mkPerasParams cert
    -- mkPerasParams is a hardcoded default; no committee lookup, no aggSig check
    = Right (ValidatedPerasCert cert)   -- passes unconditionally or with trivial checks
  addCert (WithArrivalTime now (ValidatedPerasCert cert))
    -> implAddCert: round R not in pcdsCertIds, insert unconditionally
    -> pcdsCertIds = {R}, pcdsLatestCertSeen = Just cert

getWeightSnapshot:
  -> returns weight for B_adversarial at round R
  -> chain selection now boosts B_adversarial
```

The injected certificate persists in the `PerasCertDB` for the lifetime of the node (until garbage-collected by slot), continuously biasing chain selection toward the adversarial block. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
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
