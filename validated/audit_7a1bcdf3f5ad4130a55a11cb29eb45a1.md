### Title
Missing Peras Certificate Validation Allows Unprivileged Peer to Corrupt Chain-Selection Weights — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally accepts every inbound Peras certificate without performing any cryptographic, round-number, or block-reference check. Analogous to the external report's missing zero-check that lets `_rewardsAmount = 0` silently corrupt the TPSS linked list, this missing validation gate lets any unprivileged peer inject a crafted certificate that silently corrupts the node's `PerasWeightSnapshot`, causing chain selection to assign illegitimate weight to an adversarial fork.

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory approval gate before a certificate is stored and used for chain selection. The only production instance — the catch-all `instance StandardHash blk => BlockSupportsPeras blk` — implements it as:

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

The stub returns `Right` for every input, meaning:
- No cryptographic signature over the certificate is verified.
- No round-number monotonicity is enforced; a certificate for round 0 or any already-seen round is accepted.
- No check that the boosted block exists or is on a valid chain.
- No quorum membership or committee-selection check.

The certificate then flows through the inbound path:

```
processCerts → validateCert (= validatePerasCert mkPerasParams) → addCert → PerasCertDB.implAddCert
``` [2](#0-1) 

Once stored, `implGetWeightSnapshot` rebuilds the `PerasWeightSnapshot` from every certificate in `pcdsCertsByTicket`:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [3](#0-2) 

`totalWeightOfFragment` then adds this snapshot's boost to the raw chain length when comparing candidates:

```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
``` [4](#0-3) 

Chain selection in `chainSelection` uses `preferAnchoredCandidate` which incorporates this total weight, so an illegitimate boost directly influences which fork is selected. [5](#0-4) 

The analogy to the external report is direct: just as `_rewardsAmount = 0` bypasses the TPSS increment and silently corrupts the epoch linked list, a certificate with any content bypasses `validatePerasCert` and silently corrupts the weight snapshot used by downstream chain-selection arithmetic.

### Impact Explanation

An unprivileged peer can send a crafted certificate whose `pcCertBoostedBlock` points to a block on an adversarial or weaker fork. Because `validatePerasCert` accepts it unconditionally, the node's `PerasWeightSnapshot` is updated with an illegitimate weight boost for that block. `totalWeightOfFragment` returns an inflated value for the adversarial fork, and `preferAnchoredCandidate` may select it over the honest chain. This is a chain-selection safety failure: an honest node can be made to prefer a non-canonical chain solely through a crafted network message, with no stake majority or key compromise required.

### Likelihood Explanation

The Peras certificate inbound path is wired into the diffusion layer via `makePerasCertPoolWriterFromChainDB`:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)   -- stub always returns Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [6](#0-5) 

Any peer that can connect to the node can send certificates over this mini-protocol. The stub is the only production instance; no more-specific override exists for `ShelleyBlock` or `CardanoBlock`. The issue is active whenever Peras certificate handling is enabled.

### Recommendation

Implement the actual validation logic in `validatePerasCert` before the Peras certificate path is enabled in production:

1. Verify the certificate's cryptographic signature against the committee's aggregate key.
2. Enforce round-number monotonicity: the certificate's round must be strictly greater than the last certified round stored in the node's state.
3. Verify that `pcCertBoostedBlock` refers to a block that exists and is on a valid chain.
4. Verify that the certificate was produced by a legitimate quorum (sufficient committee stake).

Until these checks are in place, the `addCert` path should reject all inbound certificates or the mini-protocol should remain disabled.

### Proof of Concept

1. Node N has Peras certificate handling active (mini-protocol wired via `makePerasCertPoolWriterFromChainDB`).
2. Adversary A connects to N and sends a crafted `PerasCert`:
   - `pcCertRound = <any large round number>`
   - `pcCertBoostedBlock = <point of a block on adversarial fork F>`
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right` unconditionally.
4. The certificate is inserted into N's `PerasCertDB` via `implAddCert`; `pcdsCertsByTicket` and `pcdsCertIds` are updated.
5. `implGetWeightSnapshot` rebuilds the `PerasWeightSnapshot` including a boost of `perasWeight params` for the adversarial block's point.
6. When a block extending fork F arrives, `chainSelectionForBlock` calls `preferAnchoredCandidate`, which calls `totalWeightOfFragment` on fork F's fragment; the illegitimate boost inflates F's total weight above the honest chain's.
7. N switches to fork F — a non-canonical chain selected solely due to the missing validation gate.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L313-317)
```haskell
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```
