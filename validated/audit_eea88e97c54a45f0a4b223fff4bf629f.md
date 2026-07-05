### Title
Unconditional Peras Certificate Acceptance Without Cryptographic or Epoch-Nonce Validation Enables Chain-Selection Manipulation - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic signature check or epoch-nonce/committee-membership verification. This stub is wired directly into the production peer-certificate ingestion path (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can therefore inject arbitrary certificates that boost any block, manipulating chain selection in favour of a non-canonical chain.

### Finding Description

**Root cause.** The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate for accepting a certificate received from a peer. Its only concrete instance — the universal default `instance StandardHash blk => BlockSupportsPeras blk` — implements the method as an unconditional `Right`:

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

No cryptographic aggregate-signature check, no epoch-nonce check (the nonce is the parameter that determines which committee members may legitimately issue a certificate for a given round), and no round-number range check are performed. [1](#0-0) 

**Production wiring.** Both production pool-writer constructors pass this stub directly as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

**Ingestion path.** `processCerts` is the function that receives a batch of certificates from a peer, calls `validateCert` on each one, and — if all pass — timestamps and stores them:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validateCert` is the stub, every certificate in every batch passes, and each is stored with a `vpcCertBoost` weight derived from `perasWeight params`. [5](#0-4) 

**Analogy to the reference bug.** In the reference report, joining a `StakedWal` in the withdrawal state omits the `activation_epoch` check; that epoch is the parameter used to compute share amounts, so its absence lets an attacker conflate objects with different share bases and gain extra rewards. Here, the missing checks are the epoch nonce and aggregate signature — the epoch nonce is exactly the parameter used to derive which committee seats are eligible to issue a certificate for a given round (see `epochNonce committee` in `WFALS.verifyCert`). Skipping it means a certificate for any round, boosting any block, is accepted as if it were legitimately produced by the correct committee. [6](#0-5) 

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost` weight that is added to the chain-selection score of the boosted block. By injecting a certificate that names an attacker-controlled block as `pcCertBoostedBlock`, an adversary can make an honest node's chain-selection logic prefer a non-canonical fork over the honest chain. This is a **High** impact: an unprivileged peer can cause an honest node to prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is a peer-facing network endpoint. Any node that connects as a peer can send a crafted certificate batch. The stub validation offers zero resistance. The only existing filter is deduplication by round number (`Set.member roundNo certIds`), which an attacker trivially bypasses by using a fresh round number. [7](#0-6) 

### Recommendation

Replace the stub `validatePerasCert` default implementation with a real implementation that:
1. Verifies the aggregate BLS/committee signature against the epoch nonce of the round in which the certificate was issued (mirroring the checks already present in `WFALS.verifyCert`).
2. Checks that `pcCertRound` falls within the valid window relative to the current chain tip.
3. Verifies that `pcCertBoostedBlock` refers to a block that actually exists on a known chain fragment.

Until the real implementation is in place, inbound certificates from peers should be quarantined rather than accepted unconditionally.

### Proof of Concept

1. Connect to a target node as a peer via the ObjectDiffusion mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = <point of attacker-controlled block>`.
3. Send the certificate in a batch to the target node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert (perasWeight mkPerasParams))` unconditionally.
5. The certificate is stored in the `PerasCertDB` / `ChainDB` with a positive boost weight.
6. Chain selection now scores the attacker-chosen block higher than it would without the certificate, potentially causing the node to switch to the attacker's fork. [1](#0-0) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L578-583)
```haskell
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
            vrfOutputs
```
