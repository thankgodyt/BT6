### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance for `StandardHash blk` implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate without performing any cryptographic or structural validation. Because `processCerts` in the Peras certificate inbound path uses this function as its sole gatekeeper before inserting certificates into the `PerasCertDB`, any unprivileged peer can inject arbitrary `PerasCert` objects. Those objects are then used by chain selection to boost the weight of any block the attacker designates, mirroring the external report's root cause: an access-control mechanism that does not enforce the Principle of Least Privilege and therefore grants every caller the same unrestricted access to a privileged operation.

### Finding Description

**Root cause — stub validation always succeeds**

In `SupportsPeras.hs` the catch-all `BlockSupportsPeras` instance reads:

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

No signature check, no quorum check, no structural check — every `PerasCert` is unconditionally wrapped in `ValidatedPerasCert` and returned as `Right`. [1](#0-0) 

**Inbound path — `processCerts` relies entirely on `validateCert`**

`makePerasCertPoolWriterFromChainDB` wires the stub directly into the inbound object-pool writer:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

`processCerts` then calls `validateCert` on every certificate received from a peer; if all return `Right` the entire batch is forwarded to `ChainDB.addPerasCertAsync`. [2](#0-1) 

Because the stub never returns `Left`, the "reject the whole batch" branch of `processCerts` is unreachable: [3](#0-2) 

**Chain-selection impact — injected certs alter block weight**

`ValidatedPerasCert.vpcCertBoost` is read by `getPerasWeightSnapshot` and fed into `preferAnchoredCandidate` / `chainSelection`. A certificate for a block on a competing fork raises that fork's chain weight by `perasWeight params`, potentially making it preferred over the honest tip. [4](#0-3) 

**Analogy to the external report**

The external report's `acceptedContracts` list granted both `LendingMarketController` and `ReserveFund` identical, unrestricted access to every privileged `TokenVault` function. Here, `validatePerasCert` is the analogous "access-control gate": it is supposed to admit only legitimately signed, quorum-backed certificates, but instead admits every caller (every peer) unconditionally, granting all of them the same unrestricted ability to insert weight-boosting entries into the consensus state.

### Impact Explanation

An unprivileged peer can inject a `PerasCert` pointing at any block already present in the node's `VolatileDB`. The injected certificate boosts that block's chain weight by `perasWeight params`. If a competing fork exists in the `VolatileDB` — a routine occurrence during normal operation — the attacker can tip chain selection toward that fork without possessing any stake, keys, or operator access. This constitutes a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical chain beyond the intended security assumptions.

### Likelihood Explanation

**High.** The Peras certificate object-diffusion mini-protocol is open to any connected peer. No authentication, stake ownership, or special role is required to send a `PerasCert` message. The attack is deterministic and requires only a single crafted message.

### Recommendation

1. Implement genuine cryptographic and quorum validation inside `validatePerasCert` before the Peras certificate mini-protocol is enabled on any network. At minimum, verify the aggregate signature over the certificate body and confirm that the signing committee members collectively hold stake above the quorum threshold.
2. Until proper validation is in place, gate the inbound certificate path behind a feature flag that is disabled by default, so the stub cannot be reached from the network.
3. Apply the Principle of Least Privilege: separate the validation logic needed by the inbound peer path from the internal forging path (`forgePerasCert`), so that each caller has access only to the operations it requires.

### Proof of Concept

1. Attacker connects to a target node as a standard peer via the Peras certificate mini-protocol.
2. Attacker observes (or guesses) a block hash present in the node's `VolatileDB` that belongs to a competing fork.
3. Attacker constructs a `PerasCert { pcCertRound = r, pcCertBoostedBlock = forkBlockPoint }` for that block.
4. Attacker sends the certificate to the node.
5. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally. [5](#0-4) 
6. The certificate is timestamped and inserted into `PerasCertDB` via `ChainDB.addPerasCertAsync`.
7. On the next chain-selection run, `getPerasWeightSnapshot` includes the injected boost for the fork block, raising its chain weight by `perasWeight params`.
8. If the fork's boosted weight exceeds the current selection's weight, the node switches to the attacker-designated fork, diverging from the canonical chain.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-632)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
```
