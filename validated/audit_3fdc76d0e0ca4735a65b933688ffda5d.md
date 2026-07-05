### Title
Unconditional Peras Certificate Acceptance in `validatePerasCert` Allows Peer-Injected Chain Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every inbound certificate without any cryptographic or semantic verification. This function is the sole validation gate in `processCerts`, which is the handler for Peras certificates received from unprivileged peers via the object diffusion mini-protocol. Any peer can inject a crafted `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, causing the receiving node to store and act on a phantom certificate that boosts an adversary-chosen block in chain selection.

### Finding Description

**Root cause — unconditional stub in the production instance:**

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the only `BlockSupportsPeras` instance (the "degenerate instance for all blks") implements `validatePerasCert` as:

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

This unconditionally wraps any certificate in `Right`, skipping every check that a real implementation must perform:
- Aggregate BLS signature verification (`pcSignature` field of `V1.PerasCert`)
- Voter eligibility proof verification (persistent/non-persistent VRF proofs in `pcVoters`)
- Quorum threshold check (whether the claimed voters actually constitute a quorum)
- Round number validity (whether `pcCertRound` corresponds to a real Peras round)
- Boosted block existence/validity (`pcBoostedBlock` is never cross-checked against the chain)

**Attacker-controlled entry path:**

`processCerts` in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` is the inbound handler for peer-supplied certificates. Both production writers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) pass `validatePerasCert mkPerasParams` as the validation callback:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
```

`processCerts` calls `validateCert` on each certificate not already in the DB. Because `validatePerasCert` always returns `Right`, every certificate passes, and `ChainDB.addPerasCertAsync` is called unconditionally, storing the certificate and triggering chain selection side-effects.

**Exploit flow:**

1. An unprivileged peer connects to a victim node via the object diffusion mini-protocol.
2. The peer crafts a `PerasCert` with `pcCertRound = r` and `pcBoostedBlock = B_adv`, where `B_adv` is the hash of an adversarial or non-canonical block.
3. The peer sends this certificate to the victim node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` without any verification.
5. `ChainDB.addPerasCertAsync` stores the certificate and triggers chain selection.
6. The Peras chain selection logic applies the boost weight (`vpcCertBoost`) to `B_adv`, causing the node to prefer the adversarial chain over the honest canonical chain.
7. The node switches to the adversarial chain, diverging from the honest network.

### Impact Explanation

**Impact: High** — Chain selection manipulation. An unprivileged peer can make an honest node prefer a non-canonical chain by injecting phantom Peras certificates that boost an adversary-chosen block. Because `validatePerasCert` never verifies the aggregate BLS signature, voter eligibility, or quorum, there is no cryptographic barrier. The Peras boost weight applied to the adversarial block can exceed the honest chain's weight, causing permanent chain divergence. This violates the core Peras safety property that only blocks with a genuine quorum of committee votes receive a boost.

### Likelihood Explanation

**Likelihood: High** — The entry path requires only a standard peer connection; no credentials, stake, or key material are needed. The object diffusion mini-protocol is open to any peer. The stub is the only `BlockSupportsPeras` instance in the codebase and is used unconditionally for all block types. The `TODO` comment and linked issue confirm this is a known placeholder, not a deliberate design choice, but the code is production-reachable today.

### Recommendation

Replace the stub `validatePerasCert` with a complete implementation that:
1. Reconstructs the aggregate BLS verification key from the claimed voter seat indices and the committee's public keys.
2. Verifies the aggregate BLS signature (`pcSignature`) over `hash(pcRoundNo, pcBoostedBlock)`.
3. Verifies each non-persistent voter's VRF eligibility proof against the epoch nonce and round number.
4. Checks that the total stake of the claimed voters meets the quorum threshold.
5. Validates that `pcCertRound` falls within the current or recent Peras window.

Until the full implementation is ready, the stub should at minimum reject all inbound certificates (return `Left PerasValidationErr`) rather than accept them unconditionally, preventing peer-driven chain selection manipulation.

### Proof of Concept

The following code path demonstrates the unconditional acceptance:

```
peer sends PerasCert { pcCertRound = r, pcBoostedBlock = B_adv, pcVoters = <anything>, pcSignature = <anything> }
  → ObjectDiffusion mini-protocol handler
  → makePerasCertPoolWriterFromChainDB.opwAddObjects [cert]
  → processCerts ... (validatePerasCert mkPerasParams) (ChainDB.addPerasCertAsync chainDB) [cert]
  → validatePerasCert mkPerasParams cert
  → Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })
  → ChainDB.addPerasCertAsync chainDB (WithArrivalTime now validatedCert)
  → chain selection applies boost to B_adv
  → node switches to adversarial chain
```

The stub at [1](#0-0)  unconditionally returns `Right` for every certificate. [2](#0-1) 

The production writer passes this stub directly as the validation callback: [3](#0-2) 

`processCerts` applies `validateCert` to each peer-supplied certificate and stores all that pass: [4](#0-3) 

The concrete `V1.PerasCert` type carries an aggregate BLS signature field (`pcSignature`) that is never verified by the stub: [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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
