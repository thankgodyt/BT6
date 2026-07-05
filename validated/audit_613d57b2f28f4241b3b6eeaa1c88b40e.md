### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function performs zero validation and unconditionally returns `Right` for every certificate it receives. Because this is the only instance in the codebase and is wired directly into the production inbound-certificate processing path (`processCerts` → `makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject an arbitrary crafted Peras certificate — with any round number, any boosted-block pointer, and any boost weight — and have it accepted, stored, and used to influence chain selection.

### Finding Description

`validatePerasCert` in the sole `BlockSupportsPeras` instance is a stub that always succeeds:

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

No check is performed on:
- The certificate's cryptographic aggregate BLS signature
- Whether the claimed `pcCertRound` is within a valid window relative to the current chain tip
- Whether the `pcCertBoostedBlock` (the block being weight-boosted) actually exists in the node's VolatileDB or is on any valid chain
- Whether the boost weight (`vpcCertBoost`) is within the protocol-permitted maximum rollback weight
- Whether the certificate's voter set constitutes a legitimate quorum

The production inbound path calls this stub directly. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

Inside `processCerts`, the result of `validateCert` is pattern-matched: if all results are `Right`, every certificate is forwarded to `addCert` (i.e., `ChainDB.addPerasCertAsync`). Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every inbound certificate is unconditionally stored and queued for chain selection:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Once a `ValidatedPerasCert` is in the ChainDB, it is used by chain selection to assign a weight boost to the certified block. The `addPerasCert` model confirms that any cert whose boosted block is not yet immutable triggers a full `chainSelection` pass:

```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
``` [4](#0-3) 

The `PerasWeightSnapshot` is then used during chain selection to prefer the boosted block's chain over the current selection, as documented in the `getPerasWeightSnapshot` API field. [5](#0-4) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that:
1. Names any volatile block as `pcCertBoostedBlock` — including a block on a minority or adversarial fork.
2. Assigns an arbitrarily large `vpcCertBoost` (the weight used in chain selection).
3. Claims any `pcCertRound` not yet seen by the node.

Because no signature, round-validity, or boosted-block-existence check is performed, the certificate passes `processCerts` and is stored. Chain selection then treats the adversarially chosen block as having received a legitimate Peras quorum boost, potentially causing the honest node to switch away from the canonical chain to a non-canonical fork. This is a bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain-selection manipulation — matching the **Critical** impact class (bypass of Peras certificate checks enabling unauthorized certificate acceptance) and the **High** impact class (chain selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain).

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a public, peer-facing interface. Any node that connects as a peer can send a batch of `PerasCert` objects. The only existing guard is a duplicate-round-number filter (`certsNotAlreadyInDb`), which is trivially bypassed by using a fresh `pcCertRound` value. No authentication, stake proof, or cryptographic check stands between the peer and the `addPerasCertAsync` call. Likelihood is **High** once the Peras object-diffusion protocol is active on the network.

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that checks, at minimum:
1. The aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the claimed voter set.
2. That `pcCertRound` falls within the current valid Peras round window.
3. That `pcCertBoostedBlock` refers to a block that is present in the VolatileDB and is on a chain that extends the immutable tip.
4. That the voter set's combined stake meets the quorum threshold.
5. That `vpcCertBoost` does not exceed the protocol-configured maximum rollback weight.

Until a real implementation is available, the inbound certificate path should reject all certificates rather than accept all of them, to avoid the current all-pass behaviour.

### Proof of Concept

A malicious peer performs the following steps:

1. Connect to the target node via the Peras object-diffusion mini-protocol.
2. Observe the node's current volatile chain to identify a minority-fork block `B_adv` at slot `s` that the node has downloaded but not selected.
3. Craft a `PerasCert { pcCertRound = freshRound, pcCertBoostedBlock = point(B_adv), pcVoters = emptyVoterSet, pcSignature = zeroBLSSignature }`.
4. Send the certificate to the target node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` without inspecting the signature or voter set.
6. The certificate is forwarded to `ChainDB.addPerasCertAsync`.
7. Chain selection runs; the adversarial block `B_adv` now carries a Peras weight boost and may be preferred over the honest canonical tip, causing the node to roll back and adopt the adversarial fork. [1](#0-0) [6](#0-5)

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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L467-472)
```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```
