### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Inject Fraudulent Chain-Selection Boosts - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural validation whatsoever. Because this function is wired directly into the network-facing Peras certificate diffusion inbound path (`processCerts` → `makePerasVotePoolWriterFromChainDB`), any unprivileged peer can send a crafted `PerasCert` for an arbitrary block, have it accepted as valid, stored in `PerasCertDB`, and used to boost that block's weight in chain selection — potentially causing an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The catch-all `BlockSupportsPeras` instance (the only instance in the codebase) defines `validatePerasCert` as:

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

This always returns `Right`, regardless of the certificate's content, round number, boosted block, or any cryptographic proof. [1](#0-0) 

**Network entry path — `processCerts` uses this stub directly:**

`makePerasVotePoolWriterFromChainDB` (the production cert pool writer) passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` filters out already-known round numbers, then calls `validateCert` on each remaining certificate. Since `validatePerasCert` always returns `Right`, every new certificate from every peer passes: [3](#0-2) 

**Accepted certificates influence chain selection:**

Accepted certificates are stored in `PerasCertDB`. The `getWeightSnapshot` method returns Peras weights for all stored certificates, and chain selection uses these weights to prefer boosted blocks: [4](#0-3) 

**Contrast with vote validation — the mitigation gap:**

For votes, the production `NodeToNode.hs` wiring passes an empty stake distribution (`PerasVoteStakeDistr mempty`), causing all votes to fail `validatePerasVote`'s stake-membership check. No equivalent mitigation exists for certificates — `validatePerasCert` ignores all inputs and always succeeds: [5](#0-4) 

**The degenerate instance is the only instance:**

The comment explicitly states this is a catch-all stub for all block types, with no more specific Cardano instance providing real validation: [6](#0-5) 

### Impact Explanation

**High — Chain selection bug enabling non-canonical chain preference.**

An unprivileged peer can:
1. Craft a `PerasCert` claiming any arbitrary block (including a non-canonical or adversarial block) won a Peras round.
2. Send it over the Peras certificate diffusion mini-protocol.
3. The receiving node accepts it unconditionally, stores it in `PerasCertDB`, and applies its `PerasWeight` boost to that block in chain selection.
4. If the boosted block is on a weaker or adversarial chain, the honest node may switch to that chain, violating chain-selection safety.

This matches the allowed impact category: **High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.**

### Likelihood Explanation

**High likelihood.** The Peras certificate diffusion mini-protocol is wired into the production `NodeToNode` handler stack (the `cPerasCertDiffusionCodec` is present in the `Codecs` record and the `hPerasCertDiffusionClient` handler is registered). Any peer that speaks the Peras cert diffusion protocol can send crafted certificates. No special keys, stake, or privileges are required — only the ability to connect as a node-to-node peer, which is open to the public. [7](#0-6) 

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that verifies:
1. The certificate's aggregate BLS signature over `(roundNo, boostedBlock)` against the expected committee's aggregate verification key.
2. That the round number falls within the valid window relative to the current chain tip.
3. That the boosted block point is a known, valid block on a plausible chain.

Until real validation is implemented, the inbound cert diffusion handler should be disabled or gated behind a feature flag, analogous to how the vote diffusion handler is effectively neutralized by passing an empty stake distribution.

### Proof of Concept

A node running the Peras-enabled build can be targeted as follows:

1. Connect to the victim node as a peer speaking the Peras cert diffusion mini-protocol.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of adversarial block>`.
3. Send it via the `objectDiffusionOutbound` protocol.
4. The victim's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in `PerasCertDB` and its boost weight is returned by `getWeightSnapshot`.
6. Chain selection now treats the adversarial block as having Peras boost weight, potentially causing the victim to switch to the adversarial chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L428-440)
```haskell
data Codecs blk addr e m bCS bSCS bBF bSBF bTX bPCD bPVD bKA bPS = Codecs
  { cChainSyncCodec :: Codec (ChainSync (Header blk) (Point blk) (Tip blk)) e m bCS
  , cChainSyncCodecSerialised ::
      Codec (ChainSync (SerialisedHeader blk) (Point blk) (Tip blk)) e m bSCS
  , cBlockFetchCodec :: Codec (BlockFetch blk (Point blk)) e m bBF
  , cBlockFetchCodecSerialised ::
      Codec (BlockFetch (Serialised blk) (Point blk)) e m bSBF
  , cTxSubmission2Codec :: Codec (TxSubmission2 (GenTxId blk) (GenTx blk)) e m bTX
  , cPerasCertDiffusionCodec :: Codec (PerasCertDiffusion blk) e m bPCD
  , cPerasVoteDiffusionCodec :: Codec (PerasVoteDiffusion blk) e m bPVD
  , cKeepAliveCodec :: Codec KeepAlive e m bKA
  , cPeerSharingCodec :: Codec (PeerSharing addr) e m bPS
  }
```
