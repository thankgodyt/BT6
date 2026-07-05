### Title
Peras Certificate Validation Stub Always Accepts Any Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance ships a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. This stub is wired directly into the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB`) used by the Peras object-diffusion mini-protocol. Any unprivileged peer can therefore inject arbitrary, structurally-crafted `PerasCert` objects that are accepted, stored in `PerasCertDB`, re-diffused to other nodes, and applied as weight boosts during chain selection.

### Finding Description

**Root cause — stub validation that always succeeds:**

The `BlockSupportsPeras` instance for all block types contains the following stub:

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

No signature is verified, no committee membership is checked, no round-number bounds are enforced, and no block-point validity is confirmed. The function accepts every input unconditionally.

**Attacker-controlled entry path — production inbound certificate handler:**

`processCerts` in `PerasCert.hs` is the handler that processes batches of inbound `PerasCert` objects received from a remote peer. It calls the injected `validateCert` function for each certificate not already in the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

The production writer, `makePerasCertPoolWriterFromChainDB`, passes `validatePerasCert mkPerasParams` as the `validateCert` argument:

```haskell
opwAddObjects = \certs ->
  processCerts
    systemTime
    (ChainDB.getPerasCertIds chainDB)
    -- TODO replace when actual plumbing is in place
    (validatePerasCert mkPerasParams)
    (void . ChainDB.addPerasCertAsync chainDB)
    certs
``` [3](#0-2) 

Because `validatePerasCert` always returns `Right`, every certificate sent by a peer passes "validation" and is added to the `PerasCertDB` and then forwarded to `ChainDB.addPerasCertAsync`, which triggers chain-selection side-effects.

**Parallel issue — `validatePerasVote` omits signature verification:**

The same stub instance's `validatePerasVote` only checks whether the claimed voter ID appears in the stake distribution; it performs no cryptographic signature check over the vote content:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [4](#0-3) 

Any peer can forge votes attributed to any committee member simply by knowing their `PerasVoterId`, which is public. These forged votes are processed by `processVotes` in `PerasVote.hs` and fed into the vote-aggregation and certificate-forging pipeline. [5](#0-4) 

### Impact Explanation

**Bypass of Peras certificate and vote verification.** An unprivileged peer can:

1. Craft a `PerasCert` pointing to any block at any round number. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and re-diffused to all connected nodes.
2. The accepted certificate carries `vpcCertBoost = perasWeight params`, which is applied as a chain-selection weight boost to the attacker-chosen block. This lets an attacker make an honest node prefer a non-canonical or adversarially-chosen chain over the legitimate heaviest chain.
3. Craft `PerasVote` objects attributed to any committee member (voter IDs are public). Because `validatePerasVote` does not verify any signature, forged votes accumulate stake weight and can trigger certificate forging for an attacker-chosen block target, compounding the chain-selection manipulation.

This satisfies:
- **Critical**: Bypass of Peras certificate/vote checks enabling unauthorized certificate acceptance.
- **High**: Chain-selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain via illegitimate weight boosts.

### Likelihood Explanation

The Peras object-diffusion mini-protocol is wired into the production `ChainDB` path. Any peer that can establish a node-to-node connection (no credentials required) can send crafted `PerasCert` or `PerasVote` messages. The stub is the **only** validation gate; there is no secondary check downstream. The TODO comments confirm this is a known incomplete state, but the code is compiled into production binaries and the handlers are active.

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation — verify the aggregate signature over the certificate content using the committee's public keys, check that the certified block point exists on a known chain, and enforce round-number bounds before returning `Right`.

2. **`validatePerasVote`**: Add cryptographic signature verification over the vote payload (round number + block point) using the voter's registered verification key, in addition to the existing stake-distribution membership check.

3. Until real validation is implemented, the stub instance should either be removed from the production code path or the mini-protocol handlers should be gated behind a feature flag that is disabled by default, so that the unvalidated path is not reachable from an unprivileged peer.

### Proof of Concept

**Preconditions:** Attacker has a standard node-to-node TCP connection to a victim node running a build that includes the Peras object-diffusion mini-protocol.

**Steps:**

1. Attacker connects to the victim node and initiates the Peras certificate object-diffusion mini-protocol session.
2. Attacker sends a `PerasCert` message with:
   - `pcCertRound` = any round number not yet in the victim's `PerasCertDB`
   - `pcCertBoostedBlock` = the `Point` of any block the attacker wishes to boost (e.g., a block on a minority fork)
3. `processCerts` on the victim calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is added to `PerasCertDB` and `ChainDB.addPerasCertAsync` is called, triggering chain selection with the attacker-chosen block receiving a weight boost equal to `perasWeight params`.
6. If the boosted block is on a competing fork, the victim node may switch to that fork, diverging from the canonical chain.
7. The victim re-diffuses the accepted certificate to its own peers, propagating the attack.

**Expected outcome:** The victim node accepts and stores the forged certificate without any error, applies the weight boost to the attacker-chosen block, and potentially reorganises its chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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
