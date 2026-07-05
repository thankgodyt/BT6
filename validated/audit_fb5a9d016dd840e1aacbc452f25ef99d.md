### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Returns `Right` for All Inbound Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The global `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every inbound Peras certificate, performing no cryptographic or structural checks. Both production certificate-pool writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) call this stub via `validatePerasCert mkPerasParams`. An unprivileged peer can therefore inject arbitrary, structurally invalid Peras certificates into the node's `PerasCertDB` and `ChainDB`, causing the node to accept and act on fraudulent boost weights during chain selection.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for accepting inbound certificates. The production instance, installed for all block types via an overlapping instance, is explicitly marked as a placeholder:

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

This stub accepts every certificate unconditionally and assigns it the full `perasWeight` boost.

Both production pool writers pass this stub directly as the validation function:

```haskell
-- makePerasCertPoolWriterFromCertDB
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
```

The `processCerts` function in `PerasCert.hs` calls `validateCert` on each inbound certificate and only rejects a batch if `validateCert` returns `Left`. Since `validatePerasCert` always returns `Right`, every certificate from every peer passes, regardless of:

- Whether the certificate's claimed quorum of votes was actually signed by eligible committee members
- Whether the boosted block point (`pcCertBoostedBlock`) corresponds to a real block on any chain
- Whether the round number is plausible
- Any BLS/KES/VRF cryptographic proof

The `processCerts` pipeline then calls `addCert` (either `PerasCertDB.addCert` or `ChainDB.addPerasCertAsync`), durably storing the fraudulent certificate and making it available to chain selection with a full `perasWeight` boost.

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification that enables unauthorized certificate acceptance.**

Peras certificates are the mechanism by which a quorum of stake-weighted committee members "boost" a block, increasing its chain-selection weight by `perasWeight` (currently 15 slots' worth of blocks). A node that accepts a fraudulent certificate will:

1. Apply an illegitimate boost to an adversary-chosen block point during chain selection.
2. Prefer a chain containing that boosted block over the honest chain, even if the honest chain is longer by up to `perasWeight - 1` blocks.
3. Persist this preference in the `PerasCertDB` and `ChainDB`, making it durable across restarts.

This directly enables an unprivileged peer to cause an honest node to diverge from the canonical chain by injecting a certificate that boosts an adversarial fork, constituting a consensus safety failure.

---

### Likelihood Explanation

**High.** The entry path is the standard Peras object-diffusion mini-protocol, which is reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to craft a `PerasCert` struct with an arbitrary `pcCertRound` and a `pcCertBoostedBlock` pointing to a target block, and send it via the object-diffusion protocol. The `processCerts` function will accept it without any cryptographic check.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The certificate's claimed quorum of votes carries valid cryptographic signatures from eligible committee members (BLS or the chosen scheme).
2. The aggregate stake of the signing committee members meets the `perasQuorumStakeThreshold`.
3. The `pcCertBoostedBlock` point refers to a block that exists on a known chain.
4. The `pcCertRound` is within the valid window (not expired per `perasCertMaxRounds`).

Until real validation is implemented, inbound certificates from untrusted peers should be rejected entirely rather than accepted unconditionally.

---

### Proof of Concept

1. Attacker connects to a victim node via the Peras object-diffusion mini-protocol.
2. Attacker sends a `PerasCert` with `pcCertBoostedBlock = <adversarial fork tip>` and any `pcCertRound`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. Chain selection now treats the adversarial fork as having 15 extra blocks of weight.
6. The victim node switches to the adversarial fork if the honest chain is not more than 15 blocks ahead.

**Root cause lines:** [1](#0-0) 

**Production pool writers using the stub:** [2](#0-1) [3](#0-2) 

**`processCerts` accepting all `Right` results:** [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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
