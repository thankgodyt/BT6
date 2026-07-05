### Title
Stub `validatePerasCert` Always Returns Success, Bypassing All Peras Certificate Validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance provides a `validatePerasCert` implementation that unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or committee-membership checks. Any unprivileged peer can inject arbitrary Peras certificates through the object-diffusion mini-protocol; those certificates are accepted, stored, and used to boost chain selection without any validation gate.

---

### Finding Description

`validatePerasCert` is the sole gate between a raw, peer-supplied `PerasCert` and a `ValidatedPerasCert` that carries a chain-selection boost weight. The only production instance of `BlockSupportsPeras` is the universal one:

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

This is not a conditional stub — it is the **only** instance (`instance StandardHash blk => BlockSupportsPeras blk`), so every block type in the system uses it. [2](#0-1) 

The inbound certificate processing path in `processCerts` calls this function and, because it always returns `Right`, every certificate passes the `partitionEithers` check and is unconditionally added to the database: [3](#0-2) 

Both production writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass `validatePerasCert mkPerasParams` as the validator: [4](#0-3) [5](#0-4) 

The accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the weight applied during Peras chain selection to prefer the certified block. [6](#0-5) 

A secondary, lesser issue exists in `validatePerasVote`: it only checks stake-distribution membership and skips all other validation (cryptographic signatures, committee eligibility, etc.): [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

A `ValidatedPerasCert` is the type-level proof that a certificate passed all required checks. Because `validatePerasCert` always produces one unconditionally, the `Validated` wrapper provides no security guarantee. An attacker can craft a `PerasCert` pointing to any block at any round number and have it accepted as a legitimate Peras certificate. The resulting `vpcCertBoost` weight is then applied during chain selection, allowing the attacker to make an honest node prefer a non-canonical or adversarially chosen chain — a direct Peras voting/certificate check bypass.

---

### Likelihood Explanation

**High.** The object-diffusion mini-protocol is reachable by any unprivileged peer that can establish a connection to the node. No key material, stake, or operator access is required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message. The stub is the only instance in the codebase and is active in all configurations.

---

### Recommendation

1. Implement real cryptographic and committee-membership validation inside `validatePerasCert` before the Peras object-diffusion protocol is enabled in production. At minimum, verify the certificate's aggregate signature against the claimed committee members and confirm those members held sufficient stake in the relevant epoch.
2. Similarly, complete `validatePerasVote` to verify the voter's cryptographic signature and committee eligibility, not just stake-distribution membership.
3. Until real validation is in place, gate the object-diffusion mini-protocol behind a feature flag so it is not reachable by external peers on production nodes.

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to a Cardano node that has the Peras object-diffusion mini-protocol enabled.
2. Peer sends a `PerasCert` message with `pcCertRound = <target round>` and `pcCertBoostedBlock = <adversarial block point>`.
3. `makePerasCertPoolWriterFromChainDB` receives the batch and calls `processCerts`. [8](#0-7) 

4. `processCerts` calls `validatePerasCert mkPerasParams cert`.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` without inspecting the certificate's content. [6](#0-5) 

6. `partitionEithers` sees zero errors; the certificate is passed to `ChainDB.addPerasCertAsync`.
7. ChainDB stores the certificate and applies its boost weight during the next chain-selection evaluation, causing the node to prefer the adversarially nominated block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
