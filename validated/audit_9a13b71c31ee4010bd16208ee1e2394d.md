### Title
`validatePerasCert` Stub Unconditionally Accepts All Inbound Peras Certificates, Enabling Fake Certificate Injection and Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or semantic validation. Because `processCerts` — the inbound certificate handler called for every peer-supplied `PerasCert` — delegates entirely to this function to decide acceptance, any unprivileged peer can inject arbitrary fake Peras certificates into the local `PerasCertDB` / `ChainDB`. Those certificates carry a `vpcCertBoost` weight that directly influences Peras chain selection, allowing an attacker to make an honest node prefer a non-canonical chain.

---

### Finding Description

**Vulnerable stub — `validatePerasCert` always returns `Right`**

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasCert` as:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

No check is performed on:
- Cryptographic signatures (committee aggregate BLS signature)
- Whether the claimed round number is valid or active
- Whether the boosted block actually exists on the local chain
- Whether the certificate was formed from votes that reached quorum
- Whether the voters were eligible committee members [1](#0-0) 

**Production inbound path — `processCerts` relies entirely on `validateCert`**

Both production pool writers pass `validatePerasCert mkPerasParams` as the `validateCert` argument to `processCerts`. The `processCerts` function only rejects a batch when `validateCert` returns `Left`; since it never does, every certificate from every peer is accepted and stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)   -- never reached
``` [2](#0-1) [3](#0-2) 

The `makePerasCertPoolWriterFromChainDB` function is explicitly documented as the production path (as opposed to the test-only `makePerasCertPoolWriterFromCertDB`), and both use the same stub validator: [4](#0-3) [5](#0-4) 

**Analogy to the external report**

The external report's `setbidtobuy` proceeds without checking `sell.islisted`, allowing a buyer to purchase a delisted token. Here, `processCerts` proceeds without any real check from `validatePerasCert`, allowing a peer to inject a certificate for any round and any block — including a non-canonical one — bypassing the entire Peras certificate authorization model.

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` field that is used by Peras chain selection to assign additional weight to the chain containing the boosted block. [6](#0-5) 

An attacker who injects a fake certificate pointing to a block on a minority or adversarial fork causes the honest node to assign Peras weight to that fork. If the boosted weight tips the chain-selection comparison, the node will switch to the non-canonical chain. This is a **High** impact: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The attack requires only a network connection to the victim node and the ability to send a well-formed (but cryptographically unsigned) `PerasCert` object over the object-diffusion mini-protocol. No stake, no keys, and no privileged access are needed. The object-diffusion protocol is a public peer-to-peer interface. The degenerate instance is the **only** `BlockSupportsPeras` instance in the repository and is used unconditionally for all block types in production.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS committee signature over `(electionId, candidate)`.
2. Checks that the claimed round number falls within the currently active or recently closed Peras round window.
3. Confirms that the boosted block point exists on the node's current chain or a known candidate fragment.
4. Verifies that the voters who signed the certificate were eligible committee members with sufficient combined stake to meet the quorum threshold.

Until the full implementation is ready, the `processCerts` inbound path should reject all certificates (return `Left` unconditionally) rather than accept them all, to avoid the injection vector.

---

### Proof of Concept

1. Connect to a victim node's object-diffusion endpoint for Peras certificates.
2. Construct a `PerasCert` with:
   - `pcCertRound` set to the current Peras round number (observable from the chain tip).
   - `pcCertBoostedBlock` set to the tip of an adversarial fork.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` without any check.
4. The certificate is stored in the `ChainDB` via `ChainDB.addPerasCertAsync`.
5. Chain selection now assigns Peras weight to the adversarial fork's tip block, potentially causing the honest node to switch chains. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-211)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
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
