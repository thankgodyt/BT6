### Title
Stub `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Corrupting Chain-Selection Weights — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance — the one active in all current production code paths — implements `validatePerasCert` as a stub that unconditionally returns `Right`, performing zero cryptographic or structural checks on the certificate. Any unprivileged peer can therefore inject an arbitrary `PerasCert` through the Peras certificate diffusion mini-protocol. The injected certificate is stored in the `PerasCertDB`, updates the `PerasWeightSnapshot`, and directly influences chain selection, potentially causing an honest node to prefer a non-canonical, adversarially-boosted chain.

---

### Finding Description

**Root cause — stub validation that always succeeds:**

The universal instance of `BlockSupportsPeras` is declared with an explicit TODO comment acknowledging it is a placeholder:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

No signature is verified, no round-number bounds are checked, no boosted-block existence is confirmed, and no committee membership is validated. Every certificate, regardless of content or origin, is accepted.

**Production inbound path — reachable by any peer:**

`makePerasCertPoolWriterFromChainDB` is the production writer used when the Peras cert diffusion mini-protocol receives certificates from peers. It passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each received cert; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**State corruption — PerasWeightSnapshot used in chain selection:**

`addPerasCertAsync` enqueues the cert for processing by the ChainDB background thread. `implAddCert` in `PerasCertDB.Impl` stores the cert and updates `pcdsLatestCertSeen`: [4](#0-3) 

`implGetWeightSnapshot` then derives the `PerasWeightSnapshot` from the stored certs. This snapshot is read by `chainSelection` via `getPerasWeightSnapshot` and passed into `preferAnchoredCandidate` / `compareChainDiffs`, which determines whether the node switches to a candidate chain: [5](#0-4) 

An adversary-supplied cert that names an adversarial block as `pcCertBoostedBlock` inflates that block's weight in chain selection, potentially causing the node to prefer a shorter or non-canonical fork over the honest chain.

**Parallel issue — `validatePerasVote` also skips signature verification:**

The same degenerate instance's `validatePerasVote` only checks stake-distribution membership; it never verifies the cryptographic vote signature because the degenerate `PerasVote` type carries no signature field at all: [6](#0-5) 

Any peer can forge votes for any registered pool, accumulate a fake quorum, and trigger certificate generation — compounding the cert-injection path above.

---

### Impact Explanation

**High — Chain selection bug enabling non-canonical chain preference.**

An unprivileged peer can inject a `PerasCert` naming any block as the boosted block. The `PerasWeightSnapshot` is updated with that boost. During chain selection, `preferAnchoredCandidate` uses the snapshot to compare candidate chains; a sufficiently large artificial boost can make the node switch to a fork it would otherwise reject. This violates the Peras security property that only honestly-certified blocks receive weight boosts, and can cause permanent divergence from the canonical chain without any operator fault.

---

### Likelihood Explanation

**High.** The Peras cert diffusion mini-protocol is reachable by any peer without authentication. The bypass requires no cryptographic capability — the attacker simply sends a well-formed CBOR-encoded `PerasCert` with an arbitrary `pcCertBoostedBlock`. The stub is the active production instance (not gated behind a feature flag), and the TODO comments confirm it is intentionally incomplete rather than accidentally deployed.

---

### Recommendation

1. **Block the inbound path until real validation exists.** `processCerts` / `makePerasCertPoolWriterFromChainDB` should refuse to accept any certificate when the active `validatePerasCert` implementation is the degenerate stub. A compile-time or runtime guard (e.g., a `PerasEnabled`/`PerasDisabled` flag checked before calling `processCerts`) would prevent the stub from being reachable over the network.

2. **Implement real `validatePerasCert`.** The concrete Cardano instance must verify: (a) the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's aggregate verification key; (b) that `pcCertBoostedBlock` refers to a known, non-immutable block; (c) that `pcCertRound` is within the valid window. The `EveryoneVotes` and `WFALS` committee implementations already provide `implVerifyCert` with the correct structure to follow.

3. **Apply the same fix to `validatePerasVote`.** The degenerate `PerasVote` type must carry a signature field, and `validatePerasVote` must verify it before a vote is accepted into the `PerasVoteDB`.

---

### Proof of Concept

**Private-testnet reproduction (no mainnet required):**

1. Start a node running the degenerate `BlockSupportsPeras` instance with Peras cert diffusion enabled.
2. From an attacker peer, connect via the Peras cert mini-protocol and send a `PerasCert` with:
   - `pcCertRound` = any valid round number
   - `pcCertBoostedBlock` = the hash of an adversarial block tip on a shorter fork
3. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{...}` unconditionally.
4. The cert is stored in `PerasCertDB`; `getWeightSnapshot` now returns a snapshot boosting the adversarial block.
5. When the next chain selection runs (triggered by any new block), `preferAnchoredCandidate` uses the inflated weight and may select the adversarial fork over the honest chain.

**Expected outcome:** The node switches to the adversarial fork. **Actual outcome (current code):** Same — the cert is accepted without any check, the weight snapshot is corrupted, and chain selection is manipulated.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L631-639)
```haskell
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

  -- The current chain we're working with here is not longer than @k@ blocks
  -- (see 'getCurrentChain' and 'cdbChain'), which is easier to reason about
  -- when doing chain selection, etc.
  assert (fromIntegral (AF.length curChain) <= unNonZero k) pure ()
```
