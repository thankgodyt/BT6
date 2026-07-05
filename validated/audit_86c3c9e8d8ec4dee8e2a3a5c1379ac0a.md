### Title
Stub `validatePerasCert` Unconditionally Accepts All Peras Certificates, Enabling Unprivileged Chain-Selection Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, used in production certificate-processing code paths, implements `validatePerasCert` as a stub that always returns `Right` without performing any cryptographic or structural validation. An unprivileged peer connected via the ObjectDiffusion mini-protocol can send arbitrarily crafted Peras certificates that are unconditionally accepted, stored in `PerasCertDB`, and used to inflate the Peras chain-selection weight of any block the attacker chooses, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

In `BlockSupportsPeras.hs`, the catch-all instance `instance StandardHash blk => BlockSupportsPeras blk` is explicitly labelled a "degenerate instance for all blks to get things to compile" and implements `validatePerasCert` as:

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

This stub is directly wired into the live certificate-ingestion pipeline. Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` in `ObjectPool/PerasCert.hs` pass `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (PerasCertDB.getCertIds perasCertDB)
      (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
      (void . join . atomically . PerasCertDB.addCert perasCertDB)
      certs
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and, because the stub always returns `Right`, every certificate passes and is timestamped and inserted into `PerasCertDB` via `addCert`: [3](#0-2) 

The stored certificates are then surfaced through `getWeightSnapshot`, which is consumed by both initial chain selection and the running GSM/chain-sync loop:

```haskell
initialWeights <- atomically $ PerasCertDB.getWeightSnapshot perasCertDB
chain <-
  ChainSel.initialChainSelection
    ...
    (forgetFingerprint initialWeights)
``` [4](#0-3) 

And in the running node kernel, Peras weights are fetched and fed directly into `preferAnchoredCandidate` to decide whether to switch chains:

```haskell
weights <- ChainDB.getPerasWeightSnapshot chainDB
pure $ \(headers, _lst) state ->
  ...
  GSM.WhetherCandidateIsBetter $
    shouldSwitch
      ( preferAnchoredCandidate
          (configBlock cfg)
          (forgetFingerprint weights)
          ...
      )
``` [5](#0-4) 

The root cause is structurally identical to the reported vulnerability: a component instance is created (the `ValidatedPerasCert` wrapper) without the initialization/validation step that is supposed to gate its creation, allowing an external party to inject arbitrary instances that carry the same authority as legitimately validated ones.

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

Because `validatePerasCert` always succeeds, a peer can craft a `PerasCert` that names any block as the boosted target. The resulting `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the full Peras boost weight. Once stored in `PerasCertDB`, `getWeightSnapshot` returns this weight for the attacker-chosen block. `preferAnchoredCandidate` then uses this weight when comparing the local chain against a candidate, potentially causing the node to switch to a shorter or otherwise non-canonical fork that the attacker has boosted.

---

### Likelihood Explanation

**Medium.** The ObjectDiffusion mini-protocol is a public, peer-facing interface. Any connected peer can submit certificates. No key material, stake, or operator access is required. The only limiting factor is that the Peras protocol is still under active development and may not yet be enabled on mainnet; however, the code is present in production source files and the ingestion pipeline is fully wired.

---

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies the certificate's cryptographic aggregate signature against the correct epoch's voting committee before constructing a `ValidatedPerasCert`. This mirrors the fix in the referenced report: initialize (validate) the template before it can be used.
2. Until real validation is in place, gate the ObjectDiffusion certificate-ingestion path so that it rejects all inbound certificates rather than accepting them unconditionally.
3. Implement `getVotingCommitteeForElection` in `AcrossEpochs.hs` (currently `error "TODO: implement getVotingCommitteeForElection"`) so that cross-epoch certificate validation has the correct committee context available. [6](#0-5) 

---

### Proof of Concept

1. Connect to a node via the ObjectDiffusion mini-protocol (certificate diffusion channel).
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of a non-canonical block>`.
3. Send the certificate to the node. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. `implAddCert` stores the certificate in `PerasCertDB` under a new ticket number.
5. `implGetWeightSnapshot` now returns a `PerasWeightSnapshot` that includes the attacker-chosen block with full Peras boost weight.
6. On the next chain-selection evaluation, `preferAnchoredCandidate` receives this inflated weight for the non-canonical block. If the attacker's chosen fork is otherwise competitive (e.g., same length), the Peras boost tips the comparison and the node switches to the non-canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs (L208-219)
```haskell
    initialWeights <- atomically $ PerasCertDB.getWeightSnapshot perasCertDB
    chain <-
      ChainSel.initialChainSelection
        immutableDB
        volatileDB
        lgrDB
        initChainSelTracer
        (Args.cdbsTopLevelConfig cdbSpecificArgs)
        varInvalid
        (void initialLoE)
        (forgetFingerprint initialWeights)
    traceWith initChainSelTracer InitialChainSelected
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L69-74)
```haskell
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```
