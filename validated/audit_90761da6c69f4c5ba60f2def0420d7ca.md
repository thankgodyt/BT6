### Title
Peras Certificate and Vote Validation Stubs Unconditionally Accept All Inbound Objects, Enabling Unauthorized Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` typeclass instance ships two stub validators that are wired directly into the live object-diffusion inbound path. `validatePerasCert` unconditionally returns `Right` for every certificate it receives, and `validatePerasVote` accepts any vote whose voter ID appears in the stake distribution without verifying the vote signature. An unprivileged peer can therefore inject arbitrary Peras certificates or votes that pass all validation, causing the victim node to store them and apply their weight boost during chain selection, making the node prefer an attacker-chosen non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` stub**

The catch-all instance for all block types provides:

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

Every certificate, regardless of content or cryptographic validity, is accepted and assigned the full `perasWeight` boost. [1](#0-0) 

**Root cause — `validatePerasVote` stub**

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

Only the voter ID is checked against the stake distribution; the BLS vote signature is never verified. Any attacker who knows a live pool ID (public information) can forge a vote for an arbitrary block. [2](#0-1) 

**Reachable inbound path — `processCerts`**

`processCerts` in the object-diffusion layer calls `validatePerasCert mkPerasParams` on every inbound certificate. Because the stub always returns `Right`, every certificate clears the filter and is forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

The production writer wires this directly to `ChainDB.addPerasCertAsync`: [4](#0-3) 

**Chain-selection consumption of injected weight**

`chainSelectionForBlock` reads the Peras weight snapshot atomically and passes it to `preferAnchoredCandidate`, which uses it to rank candidate chains:

```haskell
(invalid, curChain, weights) <-
  atomically $
    (,,)
      <$> (forgetFingerprint <$> readTVar cdbInvalid)
      <*> Query.getCurrentChain cdb
      <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
``` [5](#0-4) 

A forged certificate stored in `PerasCertDB` therefore directly influences which chain the node adopts.

**End-to-end exploit path**

1. Attacker connects to a victim node as an ordinary peer via the object-diffusion miniprotocol.
2. Attacker crafts a `PerasCert` with `pcCertBoostedBlock` pointing to any block hash of their choosing (e.g., a block on a minority fork).
3. `processCerts` calls `validatePerasCert mkPerasParams cert`; the stub returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB` with the full `perasWeight` boost.
5. On the next chain-selection run, `getPerasWeightSnapshot` returns the injected weight.
6. `preferAnchoredCandidate` ranks the attacker's chosen chain higher than the honest chain.
7. The victim node switches to the attacker-chosen fork.

The same path applies to `processVotes` / `validatePerasVote`: an attacker who knows any live pool ID can forge votes for an arbitrary block, accumulate enough forged votes to trigger `votesReachQuorum`, and cause the node to forge and store a certificate for the attacker's target block. [6](#0-5) 

### Impact Explanation

An unprivileged peer can make any honest node accept a Peras certificate for an arbitrary block without any cryptographic proof of committee quorum. The injected certificate adds a weight boost that `preferAnchoredCandidate` uses to rank chains, causing the victim to adopt a non-canonical fork chosen by the attacker. This is a direct bypass of Peras voting and certificate checks enabling unauthorized certificate acceptance — matching the **Critical** impact tier ("Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance").

### Likelihood Explanation

The attack requires only a standard peer connection; no keys, stake, or privileged access are needed. The attacker needs only a valid block hash (public) and a live pool ID (public from the stake distribution). The object-diffusion protocol is always active on nodes that have Peras enabled, making this trivially reachable in any private-testnet or testnet deployment of the Peras-enabled codebase.

### Recommendation

Replace the stub implementations with real cryptographic validation before the Peras object-diffusion path is enabled on any network:

- `validatePerasCert` must verify the aggregate BLS signature over the certificate's `(electionId, candidate)` pair against the committee's aggregate verification key, and confirm the voter set meets the quorum threshold.
- `validatePerasVote` must call `verifyVoteSignature` (already defined in `Committee.Class`) to check the BLS signature before accepting the vote.

Until these checks are implemented, the inbound `processCerts` and `processVotes` handlers should be disabled or gated behind a feature flag that is off by default.

### Proof of Concept

```
-- Attacker node (any peer):
let fakeCert = PerasCert
      { pcCertRound       = PerasRoundNo 1
      , pcCertBoostedBlock = <point of attacker-chosen block>
      }
-- Send fakeCert via the object-diffusion miniprotocol to the victim.
-- processCerts calls validatePerasCert mkPerasParams fakeCert
--   => always Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }
-- Certificate stored in PerasCertDB.
-- Next chainSelectionForBlock on victim reads the injected weight via
--   getPerasWeightSnapshot and ranks the attacker's block higher.
-- Victim switches to the attacker-chosen fork.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-635)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

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
