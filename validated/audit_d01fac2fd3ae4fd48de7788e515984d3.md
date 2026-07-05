### Title
Peras Certificate Verification Bypass Allows Unprivileged Peer to Inject Arbitrary Certificates and Influence Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` function in the production `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate without performing any cryptographic verification — no BLS aggregate signature check, no committee membership check, no quorum verification. An unprivileged peer can send a crafted `PerasCert` for any round number boosting any block, and the receiving node will accept it as valid and trigger chain selection for that block, potentially switching to a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub wired into the production inbound path**

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for all inbound certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only concrete instance in the codebase is the universal default instance, which applies to every block type via the `StandardHash blk` constraint:

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

This stub is directly wired into the production inbound certificate processing path in `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

The `processCerts` function receives this validator and applies it to every inbound certificate from a peer:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validateCert` always returns `Right`, every certificate in `certsNotAlreadyInDb` is passed directly to `addCert`, which is `void . ChainDB.addPerasCertAsync chainDB`. This triggers `chainSelSync`, which adds the certificate to the `PerasCertDB` and then runs chain selection for the boosted block:

```haskell
certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
...
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

**Attacker-controlled entry path**

1. Attacker connects as an ordinary peer via the Peras certificate diffusion mini-protocol (no privileged access required).
2. Attacker crafts a `PerasCert` with an arbitrary `pcCertRound` and a `pcCertBoostedBlock` pointing to a block on a minority fork.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always `Right ValidatedPerasCert{...}`.
4. The cert is added to `PerasCertDB` and `chainSelSync` triggers chain selection for the boosted block.
5. If the boosted block is present in the `VolatileDB`, the node may switch to the minority fork.

The `PerasCert` data type carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — no BLS aggregate signature, no voter list, no VRF outputs — so the attacker does not need to forge any cryptographic material:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [5](#0-4) 

The `PerasCertDB` deduplicates by round number only, so one crafted certificate per round is sufficient:

```haskell
if Set.member roundNo (pcdsCertIds pcds)
  then pure PerasCertAlreadyInDB
  else do ...
``` [6](#0-5) 

**Analog mapping to the original report**

The original report describes a state-manipulation bypass: a revoked authorization can be reinstated by replaying a previously-accepted signature because the revocation state (`signedData[hash] = false`) is not bound to the signature itself. The fix was to restrict callers.

The analog here is structurally identical in vulnerability class: the authorization gate (`validatePerasCert`) is bypassed entirely — not because a previously-valid proof is replayed, but because the gate unconditionally grants authorization to any input. Both root causes allow an unauthorized state change (chain selection for an invalid certificate) to proceed without a valid cryptographic proof.

---

### Impact Explanation

**High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer can inject a `PerasCert` boosting any block in the `VolatileDB`. The `chainSelSync` path will then run `chainSelectionForBlock` for that block, potentially causing the node to switch to a fork that would otherwise lose chain selection. Because Peras certificates add weight (`vpcCertBoost = perasWeight params`) to a block's chain, a crafted certificate can tip the balance in favor of a minority fork, violating the chain-selection invariant that only chains backed by a genuine quorum of committee votes receive a boost.

---

### Likelihood Explanation

**High.** The Peras certificate diffusion mini-protocol is a public, unauthenticated peer-to-peer channel. Any connecting peer can send a `PerasCert` message. The crafted certificate requires no cryptographic material — only a valid `PerasRoundNo` and a `Point blk` for a block already known to the target node. The attack is deterministic and requires no brute force.

---

### Recommendation

Implement the actual `validatePerasCert` logic referenced in the TODO at issue #120. At minimum, the validation must:
1. Verify the BLS aggregate vote signature against the aggregate public key of the claimed committee members.
2. Verify that the claimed voters are eligible committee members for the given round (using the epoch nonce and stake distribution).
3. Verify that the aggregate stake of the claimed voters meets the quorum threshold.

Until this is implemented, the inbound certificate path should reject all certificates (return `Left PerasValidationErr` unconditionally) rather than accept all of them, to fail safely.

---

### Proof of Concept

On a private testnet node with Peras enabled:

```
-- Craft a certificate for round 42 boosting a known minority-fork block hash H
let craftedCert = PerasCert
      { pcCertRound    = PerasRoundNo 42
      , pcCertBoostedBlock = BlockPoint (SlotNo 100) H
      }

-- Send it via the Peras cert diffusion mini-protocol as an ordinary peer
-- processCerts will call: validatePerasCert mkPerasParams craftedCert
-- → Right (ValidatedPerasCert { vpcCert = craftedCert, vpcCertBoost = perasWeight mkPerasParams })
-- → addCert → chainSelSync → chainSelectionForBlock for block H
```

The node will add the certificate to `PerasCertDB`, assign it the configured `perasWeight` boost, and run chain selection for block `H`. If `H` is the tip of a fork that is otherwise shorter than the current selection, the added weight may cause the node to switch to that fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L495-531)
```haskell
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L178-198)
```haskell
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
```
