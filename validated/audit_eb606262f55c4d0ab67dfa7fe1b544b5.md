### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Inbound Certificate, Enabling Unauthorized Chain-Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` implementation in the `BlockSupportsPeras` typeclass is a stub that unconditionally returns `Right` for every certificate, performing no cryptographic or structural checks. Because `processCerts` in the object-diffusion layer calls this function as the sole gate before storing a certificate in the `PerasCertDB`, any unprivileged peer can inject arbitrary Peras certificates that will be accepted, stored, and used to boost chain-selection weights for attacker-chosen blocks.

---

### Finding Description

The `BlockSupportsPeras` typeclass requires implementors to supply `validatePerasCert :: PerasCfg blk -> PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)`. The degenerate instance that covers all block types is:

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

This stub skips every check that a real Peras certificate must satisfy:
- No aggregate BLS signature verification over the quorum of votes.
- No check that the claimed quorum of voters actually exists in the stake distribution.
- No check that the boosted block (`pcCertBoostedBlock`) is a real point on any known chain.
- No check that the round number (`pcCertRound`) is within a valid range.

The inbound processing pipeline in `processCerts` calls this function as the only validation gate:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
```

Because `validateCert` is always `validatePerasCert mkPerasParams` and always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate from every peer is stored.

The same structural problem exists for `validatePerasVote`: it only checks whether the voter ID appears in the stake distribution map, but never verifies the vote signature or the eligibility proof (VRF output for non-persistent committee members):

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

Any peer that knows a valid `PerasVoterId` present in the stake distribution can forge votes for that voter without possessing the corresponding private key.

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` field. The `PerasCertDB` exposes `getWeightSnapshot`, which is consumed by chain selection to add Peras boost weight to candidate chains. By injecting a certificate that names an attacker-controlled block as `pcCertBoostedBlock`, an adversary causes honest nodes to assign extra chain-selection weight to that block, potentially making a non-canonical or adversarial chain preferred over the honest chain. This directly undermines the Peras safety guarantee that only a block backed by a genuine quorum of stake-weighted votes receives a boost.

This matches the **Critical** impact class: bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-weight manipulation.

---

### Likelihood Explanation

The entry path requires only a network peer connection. The object-diffusion mini-protocol is wired to call `processCerts` for every batch of inbound certificates. No special privileges, keys, or stake are required. An attacker needs only to:
1. Connect to a node as a peer.
2. Send a `PerasCert` with an arbitrary `pcCertRound` and a `pcCertBoostedBlock` pointing to any block hash.

The certificate will be stored unconditionally.

---

### Recommendation

1. **`validatePerasCert`**: Implement full aggregate BLS signature verification over the set of claimed voters, verify that the voter set constitutes a quorum of stake, and verify that `pcCertBoostedBlock` refers to a known block point. Remove the stub and replace it with the real cryptographic checks before the Peras object-diffusion layer is enabled in production.

2. **`validatePerasVote`**: Add BLS signature verification (`pvSignature`) and, for non-persistent members, VRF eligibility proof verification (`pvEligibilityProof`) before accepting a vote. Membership in the stake distribution map is a necessary but not sufficient condition.

3. Until real validation is implemented, the object-diffusion writers (`makePerasCertPoolWriterFromChainDB`, `makePerasCertPoolWriterFromCertDB`) should not be wired into a live node, or should be guarded by a feature flag that is disabled by default.

---

### Proof of Concept

The attacker-controlled entry path is:

1. Peer sends a batch containing a crafted `PerasCert blk` with `pcCertRound = r` and `pcCertBoostedBlock = someAdversarialPoint`.

2. `makePerasCertPoolWriterFromChainDB` receives the batch and calls `processCerts`: [1](#0-0) 

3. `processCerts` calls `validatePerasCert mkPerasParams` on each cert: [2](#0-1) 

4. `validatePerasCert` unconditionally returns `Right`: [3](#0-2) 

5. The cert is stored in the `PerasCertDB` and its boost weight is applied to `someAdversarialPoint` in chain selection.

The same path applies to votes via `makePerasVotePoolWriterFromChainDB` → `processVotes` → `validatePerasVote`, where only stake-map membership is checked and no signature verification occurs: [4](#0-3) [5](#0-4)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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
