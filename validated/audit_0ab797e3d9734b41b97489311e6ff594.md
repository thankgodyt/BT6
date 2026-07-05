### Title
`processCerts` Accepts Multiple Certificates Per Round Without Intra-Batch Deduplication — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

### Summary

`processCerts` filters inbound Peras certificates only against the DB snapshot taken at function entry. It performs no intra-batch duplicate-round check. A peer can send a batch containing two certificates for the same round (equivocating certificates). Both survive the filter, both pass per-certificate validation, and both are forwarded to `addCert`. The first is stored; the second is silently discarded by the DB layer. The peer is never disconnected, and the peer controls which certificate is stored by controlling the ordering of the batch.

### Finding Description

`processCerts` is the inbound handler for Peras certificates received over the object-diffusion mini-protocol:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM          -- (1) snapshot DB round-set
  let certsNotAlreadyInDb =
        filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs  -- (2) filter
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts   -- (3) add all
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [1](#0-0) 

Step (2) only removes rounds already committed to the DB at the moment of the snapshot. It does **not** deduplicate round numbers that appear more than once within the incoming batch itself. If a peer sends `[cert_R_B1, cert_R_B2]` (two certificates for round `R` boosting different blocks), both survive the filter, both are individually validated by `validateCert`, and both are passed to `addCert`. The underlying `implAddCert` atomically inserts the first and returns `PerasCertAlreadyInDB` for the second, but `processCerts` voids that result and never raises an exception:

```haskell
(void . ChainDB.addPerasCertAsync chainDB)
``` [2](#0-1) 

The `PerasCertDB` state-machine test explicitly marks equivocating-certificate inputs as a precondition violation, confirming the implementation does not handle them:

```haskell
-- Do not add equivocating certificates.
AddCert cert -> all p model.certs
 where
  p cert' =
    getPerasCertRound cert /= getPerasCertRound cert'
      || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
``` [3](#0-2) 

The current `validatePerasCert` instance is a stub that unconditionally returns `Right`:

```haskell
validatePerasCert params cert =
  Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }
``` [4](#0-3) 

### Impact Explanation

The missing intra-batch deduplication produces two concrete effects:

1. **Equivocation goes unpunished.** The protocol comment states that a batch containing any invalid certificate must cause disconnection via `PerasCertInboundException`. Sending two certificates for the same round is a certificate equivocation — a protocol violation — yet `processCerts` never throws. The peer is not disconnected and can repeat the attack indefinitely.

2. **Peer-controlled certificate injection.** Because the first certificate in the batch wins, the peer dictates which certificate for round `R` is stored. With the current always-`Right` stub validation, an unprivileged peer can supply any `(round, boostedBlock)` pair as the first element of a two-element batch, causing the node to store a certificate for an arbitrary block. That certificate then influences chain selection via `chainSelSync`, which triggers `chainSelectionForBlock` for the boosted block:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Even after real cryptographic validation is wired in, the ordering-dependent acceptance of the first certificate in a batch remains: a peer who possesses two legitimately valid certificates for the same round (possible under a misconfigured quorum threshold) can choose which one the node stores, weakening the certificate authorization guarantee.

### Likelihood Explanation

The entry path is fully unprivileged: any peer connected via the object-diffusion mini-protocol can call `opwAddObjects` with an arbitrary list of `PerasCert` values. No key material, stake, or operator access is required to craft a batch with two entries sharing the same `pcCertRound`. With the current stub validation the attack is trivially executable today; with real validation it requires two independently valid certificates for the same round.

### Recommendation

Add an intra-batch duplicate-round check inside `processCerts` before the validation step. If any two certificates in `certsNotAlreadyInDb` share the same `PerasRoundNo`, treat the batch as equivocating and throw `PerasCertValidationError` (or a dedicated equivocation error), causing the peer to be disconnected. A `Map PerasRoundNo (PerasCert blk)` fold over `certsNotAlreadyInDb` is sufficient to detect and report the collision.

### Proof of Concept

```
Peer sends batch: [ PerasCert { pcCertRound = R, pcCertBoostedBlock = B_attacker }
                  , PerasCert { pcCertRound = R, pcCertBoostedBlock = B_honest    } ]

processCerts:
  alreadyInDb = {}                          -- neither R is in DB yet
  certsNotAlreadyInDb = [cert_B_attacker, cert_B_honest]   -- both survive filter
  validateCert cert_B_attacker = Right ...  -- stub always Right
  validateCert cert_B_honest   = Right ...
  partitionEithers → ([], [vCert_B_attacker, vCert_B_honest])
  addCert vCert_B_attacker → AddedPerasCertToDB   (B_attacker stored for round R)
  addCert vCert_B_honest   → PerasCertAlreadyInDB (silently voided)
  -- No exception thrown; peer remains connected.
  -- chainSelectionForBlock is triggered for B_attacker.
``` [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L132-132)
```haskell
          (void . ChainDB.addPerasCertAsync chainDB)
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasCertDB/StateMachine.hs (L132-140)
```haskell
        -- Do not add equivocating certificates.
        AddCert cert -> all p model.certs
         where
          -- We should reject equivocating certificates, that is, certificates
          -- for the same round but boosting different blocks.
          -- So we should enforce: round = round' => boostedBlock = boostedBlock'
          p cert' =
            getPerasCertRound cert /= getPerasCertRound cert'
              || getPerasCertBoostedBlock cert == getPerasCertBoostedBlock cert'
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L531-531)
```haskell
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```
