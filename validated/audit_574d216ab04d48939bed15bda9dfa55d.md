### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates While Vote Validation Performs Checks - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` always returns `Right` with no checks whatsoever, while the sibling `validatePerasVote` performs at least a stake-distribution membership check. Any unprivileged peer can therefore inject arbitrary Peras certificates via the object-diffusion mini-protocol; every certificate is accepted unconditionally, stored in the `PerasCertDB`/`ChainDB`, and its boost weight is applied to chain selection.

---

### Finding Description

`validatePerasCert` and `validatePerasVote` are the two parallel inbound-object validation functions for the Peras extension. They are called symmetrically from `processCerts` and `processVotes` respectively, both of which are the production inbound handlers for the object-diffusion mini-protocol.

`validatePerasVote` performs a stake-distribution lookup and rejects a vote whose voter ID is not present:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

`validatePerasCert`, by contrast, performs **zero checks** and unconditionally returns `Right`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right ValidatedPerasCert
    { vpcCert = cert
    , vpcCertBoost = perasWeight params
    }
```

The production inbound path `processCerts` (called from `makePerasCertPoolWriterFromChainDB`) passes every non-duplicate certificate through `validatePerasCert`, receives `Right` for all of them, timestamps them, and stores them via `ChainDB.addPerasCertAsync`. The stored `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the weight added to a chain during Peras-aware chain selection. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

The `vpcCertBoost` weight attached to every accepted certificate is used by the Peras chain-selection logic to prefer chains that carry a certificate. Because `validatePerasCert` accepts any certificate for any `PerasRoundNo` and any `Point blk`, an attacker can:

1. Craft a `PerasCert` claiming to certify an arbitrary block on a weaker fork.
2. Deliver it to a victim node via the object-diffusion mini-protocol.
3. The certificate is stored with full boost weight (`perasWeight params`).
4. Chain selection now treats the attacker's fork as heavier than the canonical chain.

This is a **bypass of Peras certificate validation** that lets an unprivileged peer cause an honest node to prefer a non-canonical chain, matching the "Critical – bypass of Peras certificate checks" and "High – chain selection bug" categories in the allowed impact scope. [5](#0-4) 

---

### Likelihood Explanation

The entry path requires only a network connection to the victim node. The object-diffusion mini-protocol for Peras certificates is wired into the production `ChainDB` writer (`makePerasCertPoolWriterFromChainDB`). No keys, stake, or operator access are needed. Any peer that can open a connection and send a `PerasCert` message triggers the vulnerable path. [4](#0-3) 

---

### Recommendation

`validatePerasCert` must be brought to parity with `validatePerasVote` and the formal Peras specification. At minimum it should verify:

1. **Committee membership / cryptographic signature** – the certificate must be signed by a quorum of eligible committee members for the claimed round.
2. **Round number bounds** – the certificate's `pcCertRound` must be within the valid window relative to the current chain tip (analogous to the `block.timestamp > 2 hours + baseTimeStamp` check in the original report).
3. **Boosted block existence** – `pcCertBoostedBlock` must point to a block that actually exists on a known chain.

Until the full validation is implemented, the function should reject all certificates rather than accept all of them, so that the stub cannot be exploited:

```haskell
validatePerasCert _params _cert = Left PerasValidationErr
``` [1](#0-0) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to a victim node that has the Peras object-diffusion mini-protocol active.
2. Peer sends a batch containing one crafted `PerasCert`:
   ```
   PerasCert { pcCertRound = <target round>, pcCertBoostedBlock = <attacker fork tip> }
   ```
3. `processCerts` is invoked in `makePerasCertPoolWriterFromChainDB`.
4. `alreadyInDb` check passes (first time for this round number).
5. `validatePerasCert mkPerasParams cert` returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
6. `ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)` stores the certificate.
7. The Peras weight snapshot now includes a boost for the attacker's fork block.
8. Chain selection evaluates the attacker's fork as heavier than the canonical chain by `perasWeight params`.

The root cause is the single line `validatePerasCert params cert = Right ...` with no guard, in direct contrast to `validatePerasVote` which has a `| otherwise = Left PerasValidationErr` guard. [1](#0-0) [2](#0-1) [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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
