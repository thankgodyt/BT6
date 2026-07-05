### Title
Peras Certificate Verification Bypass via Unconditional `validatePerasCert` Stub Wired into Production Inbound Processing — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This stub is directly wired into both production certificate inbound processing paths (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can craft and send a `PerasCert` for an arbitrary round and block; the certificate will be accepted, stored in the `PerasCertDB`, and its boost weight applied to chain selection via the `PerasWeightSnapshot`, allowing the peer to steer the node toward a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

The `BlockSupportsPeras` type class declares `validatePerasCert` as the gate for accepting Peras certificates. The only deployed instance is the degenerate catch-all:

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
        , vpcCertBoost = perasWeight params   -- always PerasWeight 15
        }
```

Every call returns `Right` regardless of the certificate's content. No signature, no round-number bounds, no boosted-block existence check.

**Wiring into production inbound paths:**

Both production pool-writer constructors pass this stub directly as the validation callback:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
```

`processCerts` then calls this callback on every certificate received from a peer:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) -> throw (PerasCertValidationError errs)
```

Because `validateCert` never produces a `Left`, the `(errs, _)` branch is unreachable and every certificate is forwarded to `addCert`.

**Chain-selection impact:**

`PerasCertDB.getWeightSnapshot` returns a `PerasWeightSnapshot` built from all stored `ValidatedPerasCert` objects. This snapshot is consumed by chain selection to apply the `vpcCertBoost` weight to candidate chains. A fake certificate injected for round R boosting block B causes the node to add `PerasWeight 15` to B's chain density, potentially making a weaker adversarial chain appear heavier than the honest chain.

---

### Impact Explanation

**Classification:** Critical — bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.

An unprivileged peer with a single TCP connection can inject a `PerasCert` for any `(PerasRoundNo, Point blk)` pair. The certificate is accepted without any cryptographic check, stored durably in the `PerasCertDB`, and its boost weight is applied to chain selection. This allows the attacker to make the node prefer a non-canonical chain, constituting a consensus safety failure reachable from the network boundary.

---

### Likelihood Explanation

High. The attack path is a single miniprotocol message. No stake, no keys, no prior knowledge of the chain state is required. The attacker only needs to be accepted as a peer and send a well-formed CBOR-encoded `PerasCert`. The `processCerts` function will accept it unconditionally.

---

### Recommendation

1. **Immediate mitigation:** Change the degenerate `validatePerasCert` to return `Left PerasValidationErr` for all inputs until the real cryptographic implementation is in place. This is safer than accepting everything.
2. **Proper fix:** Implement the real `BlockSupportsPeras` instance for Cardano blocks with BLS aggregate-signature verification, round-number range checks, and boosted-block existence checks before wiring it into the inbound processing paths.
3. **Structural analog fix (from the original report):** The `PerasRoundVoteState` does not snapshot the `PerasCfg` (quorum threshold) at round-creation time — `updatePerasRoundVoteState` accepts a fresh `PerasCfg blk` on every call. If parameters ever become mutable (e.g., via a hard-fork era transition), the quorum threshold used for in-progress rounds could change mid-round, retroactively altering whether a certificate is forged. The quorum threshold should be snapshotted into `PerasRoundVoteState` at round creation, mirroring how `vpcCertBoost` is snapshotted into `ValidatedPerasCert`.

---

### Proof of Concept

```
1. Establish a peer connection to the target node via the Peras cert miniprotocol.

2. Craft a PerasCert targeting an adversarial block B in round R:
     PerasCert { pcCertRound = R, pcCertBoostedBlock = point(B) }

3. Send the certificate batch to the node.

4. processCerts calls (validatePerasCert mkPerasParams cert), which returns:
     Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }
   for every certificate, unconditionally.

5. The certificate is stored in PerasCertDB via addCert.

6. getWeightSnapshot now includes PerasWeight 15 for block B.

7. Chain selection adds 15 to B's chain density; if the honest chain's
   density advantage is < 15, the node switches to the adversarial chain.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L199-207)
```haskell
updatePerasRoundVoteState ::
  forall blk.
  StandardHash blk =>
  WithArrivalTime (ValidatedPerasVote blk) ->
  PerasCfg blk ->
  PerasRoundVoteState blk ->
  Either (UpdateRoundVoteStateError blk) (PerasRoundVoteState blk)
updatePerasRoundVoteState vote cfg roundState =
  assert (getPerasVoteRound vote == getPerasVoteRound roundState) $ do
```
