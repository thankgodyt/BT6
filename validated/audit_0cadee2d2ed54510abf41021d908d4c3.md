### Title
Peras Certificate and Vote Validation Bypass via Stub `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which applies to **all** block types, unconditionally accepts every inbound Peras certificate (`validatePerasCert` always returns `Right`) and accepts votes without any cryptographic signature verification (`validatePerasVote` only checks stake-distribution membership). The network-facing `processCerts` and `processVotes` functions gate certificate/vote acceptance entirely on these stub validators. An unprivileged peer can therefore inject arbitrary, cryptographically unverified certificates and votes that are stored in `PerasCertDB`/`PerasVoteDB` and used to influence Peras-based chain-selection weight.

---

### Finding Description

The `BlockSupportsPeras` type class declares two validation methods:

```haskell
validatePerasCert ::
  PerasCfg blk -> PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk -> PerasVoteStakeDistr -> PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The only concrete instance in the production source tree is the degenerate catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }

  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [1](#0-0) 

**`validatePerasCert`** unconditionally returns `Right` — no round-number check, no cryptographic proof of committee membership, no signature verification of any kind. Every certificate from every peer is stamped `ValidatedPerasCert` and assigned the full `perasWeight` boost.

**`validatePerasVote`** only checks whether the claimed voter ID appears in the public stake-distribution map. The stake distribution is public on-chain data; any observer can enumerate all valid voter IDs. Because no cryptographic signature is verified, an adversary can impersonate any registered voter and cast votes for any block and any round without possessing the corresponding key.

These stub validators are the sole gatekeepers in the network-facing ingest paths:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  ...
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _)            -> throw (PerasCertValidationError errs)
``` [2](#0-1) 

```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    ...
    mapM validateVote votesNotAlreadyInDb
  ...
  case partitionEithers validationResults of
    ([], validatedVotes) -> mapM_ (addVote . WithArrivalTime now) validatedVotes
    (errs, _)            -> throw (PerasVoteValidationError errs)
``` [3](#0-2) 

Both functions are the **only** validation barrier between the network and the `PerasCertDB`/`PerasVoteDB`. Because `validatePerasCert` never fails, every certificate a peer sends is stored. Because `validatePerasVote` skips signature verification, any peer who knows a valid voter ID (public information) can cast votes on behalf of that voter.

The `makePerasVotePoolWriterFromChainDB` function wires `validatePerasVote` directly to the ChainDB writer path:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

---

### Impact Explanation

Peras certificates boost the chain-selection weight of the blocks they reference. The `ValidatedPerasCert` carries a `vpcCertBoost` field set to `perasWeight params`; this boost is applied during chain comparison. An adversary who can inject arbitrary certificates can therefore:

1. **Boost a non-canonical block** to make it appear heavier than the honest chain tip, causing honest nodes to switch to the adversary's fork — a chain-selection safety failure.
2. **Forge a quorum of votes** (by impersonating registered voters whose IDs are public) to produce a certificate for any block, then inject that certificate to trigger the weight boost.

This matches the **Critical** impact category: bypass of certificate/vote verification checks that enables unauthorized certificate acceptance and chain-selection manipulation.

---

### Likelihood Explanation

**Medium.** The Peras certificate and vote diffusion mini-protocols are present in the production source tree and are wired to the ChainDB. The degenerate instance is the only `BlockSupportsPeras` instance compiled into production binaries. The attack requires only that the Peras diffusion protocol be active on the network — no stake, no keys, and no privileged access are needed. The primary uncertainty is whether Peras is currently enabled on mainnet; `getPerasCertInBlock _ = Nothing` indicates the block-level certificate extraction is also stubbed, which limits the ledger-state side of the integration, but the network-facing ingest path is fully wired and reachable. [5](#0-4) 

---

### Recommendation

1. **`validatePerasCert`**: Implement full cryptographic verification of the certificate's committee-membership proof and signature before the degenerate instance is used in any network-connected context. Do not ship `Right` unconditionally.
2. **`validatePerasVote`**: Add cryptographic signature verification (VRF or equivalent) in addition to the stake-distribution lookup. Knowing a voter ID is public; proving possession of the corresponding key is not.
3. Until the TODO items (cardano-peras issues #73 and #120) are resolved, gate the Peras diffusion mini-protocols behind a feature flag that is disabled by default in production builds, so the stub validators are never reachable from the network.

---

### Proof of Concept

1. Obtain the public stake distribution from the chain (public on-chain data); enumerate all registered voter IDs.
2. Connect to a target node as an unprivileged peer via the Peras certificate/vote diffusion mini-protocol.
3. Construct `PerasCert` values referencing an adversarial block at any round number — no cryptographic material required.
4. Send the batch; `processCerts` calls `validatePerasCert`, which returns `Right` unconditionally; the certificates are stored in `PerasCertDB` with full `perasWeight` boost.
5. Separately, construct `PerasVote` values claiming to be registered voters (IDs taken from the public stake distribution) targeting the same adversarial block.
6. Send the vote batch; `processVotes` calls `validatePerasVote`, which returns `Right` for every vote whose claimed voter ID appears in the stake distribution — no signature check is performed.
7. Once a quorum of votes accumulates, a certificate is forged for the adversarial block; chain selection now weights that block above the honest tip, causing the node to switch forks. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
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
