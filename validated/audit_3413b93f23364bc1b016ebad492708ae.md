### Title
Peras Certificate Validation Bypass — `validatePerasCert` Unconditionally Accepts All Inbound Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal default `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing zero validation. This is the function invoked by the production inbound-certificate processing pipeline (`processCerts`). An unprivileged peer can therefore inject arbitrary Peras certificates — with any round number and any boosted-block point — that will be accepted, stored, and forwarded to chain selection without any cryptographic or semantic check.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal default instance (lines 318–389) provides the `validatePerasCert` implementation used for every block type until a concrete override is supplied:

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

The function accepts `params` and `cert` but ignores both entirely. It performs no checks on:

- The certificate's round number (`pcCertRound`) relative to the current protocol round or the node's known certificate history.
- Whether the boosted block (`pcCertBoostedBlock`) actually exists on any known chain.
- Any cryptographic proof of quorum (VRF/KES signatures, committee membership, stake threshold).

This stub is the **only** implementation in the codebase for the `validatePerasCert` method; no concrete era-specific override exists.

The production inbound-certificate pipeline in `processCerts` calls this function directly:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both production pool writers — `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — pass `validatePerasCert mkPerasParams` as the `validateCert` argument:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [3](#0-2) [4](#0-3) 

The `makePerasCertPoolWriterFromChainDB` variant passes accepted certificates directly to `ChainDB.addPerasCertAsync`, which triggers chain-selection side-effects:

```haskell
(void . ChainDB.addPerasCertAsync chainDB)
``` [5](#0-4) 

The analog to the reported `process_payout_issuance` bug is exact:

| Reported bug | Consensus analog |
|---|---|
| No check that `current_timestamp > actual_start_datetime + length_in_seconds` before marking Matured | No check that the certificate's `pcCertRound` is valid for the current protocol round before accepting it |
| No check that `issuance.parent_bond == *bond_account_info.key` | No check that `pcCertBoostedBlock` belongs to any known chain |

---

### Impact Explanation

In the Peras protocol, a certificate boosts a specific block by adding `perasWeight` to its chain-selection score. A node that accepts a forged certificate will apply that boost to an arbitrary block chosen by the attacker, causing it to prefer a non-canonical or adversarially-chosen chain over the honest chain. Because `validatePerasCert` never rejects any certificate, an unprivileged peer can:

1. Inject a certificate claiming to boost any block at any round number.
2. Have that certificate accepted, stored, and fed into `ChainDB.addPerasCertAsync`.
3. Cause the node's chain-selection logic to apply an illegitimate weight boost, potentially switching to a non-canonical fork.

This is a complete bypass of Peras certificate/vote verification, matching the **Critical** impact class: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The Peras mini-protocol (ObjectDiffusion) is gated by `eraPerasRoundLength` in each era's `EraParams`. On current Cardano mainnet this is set to `NoPerasEnabled` (e.g., Byron sets `eraPerasRoundLength = HardFork.NoPerasEnabled`). [6](#0-5) 

However, the code is production-ready infrastructure that will be activated when Peras is enabled on a private testnet or future mainnet era. The stub is not guarded by any compile-time or runtime flag beyond the era parameter. Any operator running a Peras-enabled private testnet is immediately exposed. Likelihood is **Medium** (not yet mainnet, but reachable on any Peras-enabled network with zero attacker privilege required).

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that checks at minimum:

1. **Round validity**: `pcCertRound` must correspond to a round that is plausible given the current slot and Peras round length.
2. **Boosted-block existence**: `pcCertBoostedBlock` must refer to a block that is present in the node's chain fragment or VolatileDB.
3. **Quorum proof**: The certificate must carry a cryptographic proof that a quorum of committee members (weighted by stake) voted for the boosted block in the claimed round.

Until a real implementation is available, the stub should at minimum be removed from the universal default instance and replaced with a method that has no default, forcing each concrete block type to provide an explicit implementation before Peras can be enabled.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a crafted peer to an honest node via the Peras certificate mini-protocol.
2. Send a `PerasCert` with `pcCertRound = <any large round>` and `pcCertBoostedBlock = <point of an adversarial fork block>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{...}` unconditionally.
4. The certificate is timestamped and passed to `ChainDB.addPerasCertAsync`.
5. Chain selection applies `perasWeight` boost to the adversarial block, potentially causing the honest node to switch to the adversarial fork.

No keys, stake, or operator access are required. The only prerequisite is a TCP connection to the node's Peras mini-protocol port. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-137)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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

**File:** ouroboros-consensus-cardano/src/byron/Ouroboros/Consensus/Byron/ByronHFC.hs (L328-330)
```haskell
    _ <- CBOR.decodeMapLen
    pure (LedgerTables $ ValuesMK Map.empty)
  encodeTablesWithHint _ _ = CBOR.encodeMapLen 0
```
