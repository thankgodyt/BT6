### Title
Unconditional Peras Certificate Acceptance — No Cryptographic Authority Verification in `validatePerasCert` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass instance used in all production code paths provides a stub `validatePerasCert` that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic verification. An unprivileged peer can send a crafted `PerasCert` pointing to any block, and the node will accept it, store it, and apply its chain-selection boost weight — causing the node to prefer an adversarially chosen block over the honest canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting Peras certificates received from peers. The universal instance at line 320 of `SupportsPeras.hs` is explicitly marked as a "degenerate instance for all blks to get things to compile":

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

The stub `PerasCert blk` data type in this instance carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — no signature field exists to verify: [2](#0-1) 

This stub is wired directly into both production object-diffusion pool writers. `makePerasCertPoolWriterFromChainDB` — the path used when a node receives certificates from peers and feeds them into the `ChainDB` — calls `validatePerasCert mkPerasParams`:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`makePerasCertPoolWriterFromCertDB` (used in isolated cert-DB tests and referenced in production) does the same: [4](#0-3) 

The `processCerts` function that calls `validateCert` will accept every certificate that is not already in the DB: [5](#0-4) 

The accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which defaults to `PerasWeight 15` from `mkPerasParams`: [6](#0-5) 

This boost is applied during chain selection to prefer the boosted block over unboosted honest blocks.

The analog to the external report is exact: the SPL bug used the wrong authority (`cpi_authority_pda`) instead of the correct one (`ctx.accounts.authority`). Here, **no authority is checked at all** — the certificate's aggregate BLS signature and voter eligibility proofs (as defined in the real `PerasCert` type in `Peras/Cert/V1.hs`) are never verified because the stub instance does not even carry a signature field. [7](#0-6) 

---

### Impact Explanation

**High — Bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance and chain-selection manipulation.**

An adversary who can send a single crafted `PerasCert` message to a node via the object-diffusion mini-protocol will have that certificate unconditionally accepted and stored. The certificate's `vpcCertBoost` (weight 15) is then applied in chain selection, causing the node to prefer the adversarially nominated block over the honest canonical chain. Because the boost is persistent in the `PerasCertDB`, the effect survives across chain-selection rounds until the certificate is garbage-collected. This breaks the Peras safety guarantee that only honestly-quorum-certified blocks receive a chain-weight boost.

---

### Likelihood Explanation

**High.** The vulnerable code path is the default production path for all inbound Peras certificates. No special privileges, keys, or stake are required — any peer that can open an object-diffusion connection can send a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The only gate is the duplicate-round-number check (`Set.member roundNo alreadyInDb`), which an attacker trivially bypasses by using a fresh round number.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Deserializes the certificate using the concrete `Peras.Cert.V1.PerasCert` type (which carries `pcSignature :: AggregateVoteSignature PerasBLSCrypto` and `pcVoters`).
2. Reconstructs the aggregate BLS verification key from the declared voter set against the current stake distribution / committee selection context.
3. Calls `verifyAggregateVoteSignature` (already implemented in `EveryoneVotes.hs` and `WFALS.hs`) to verify the aggregate signature over `(pcRoundNo, pcBoostedBlock)`.
4. Verifies VRF eligibility proofs for non-persistent voters.

Until this is done, the object-diffusion cert ingest path must not be exposed to untrusted peers on any network where Peras chain-weight boosts affect chain selection.

---

### Proof of Concept

On a private testnet node with Peras object diffusion enabled:

1. Craft a `PerasCert` with `pcCertRound = <any fresh round>` and `pcCertBoostedBlock = <hash of adversary's preferred block>`.
2. Send it to the target node via the Peras certificate object-diffusion mini-protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is stored in the `PerasCertDB` / `ChainDB`.
5. Chain selection now applies a weight-15 boost to the adversary's block, causing the node to switch to the adversarially boosted fork even if the honest chain is longer by up to 14 blocks.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L50-62)
```haskell
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)
```
