### Title
Peras Certificate Verification Bypass via Unconditional `validatePerasCert` Stub Allows Unprivileged Peer to Inject Arbitrary Chain-Boosting Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally accepts every inbound `PerasCert` without performing any cryptographic, quorum, or semantic verification. This stub is wired directly into the live Peras certificate diffusion inbound handler. An unprivileged peer can craft a `PerasCert` claiming to boost any block in any round and have it accepted, stored, and applied to chain selection — bypassing the entire Peras voting and quorum process.

---

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` provides a degenerate implementation of `validatePerasCert` that always returns `Right`:

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

This stub is consumed by `makePerasCertPoolWriterFromChainDB`, which is the production pool writer for inbound Peras certificates:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

This writer is registered as the live `hPerasCertDiffusionClient` handler in `mkHandlers` inside `NodeToNode.hs`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

The `processCerts` function that drives this path validates each certificate using the supplied `validateCert` callback and, on success, timestamps and stores it: [5](#0-4) 

Because `validatePerasCert` always returns `Right`, every certificate sent by any peer passes validation and is stored. The stored certificate then contributes a `PerasWeight` boost to the `WeightedSelectView` used during chain selection: [6](#0-5) 

The `PerasCert` wire type carries only a round number and a block point — no aggregate BLS signature, no voter bitmap, no quorum proof. The concrete V1 certificate type (`Peras.Cert.V1`) does carry a signature, but the degenerate `BlockSupportsPeras` instance used in production ignores it entirely. [7](#0-6) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.**

A single unprivileged peer can:

1. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = adversarialPoint}` for any round `r` and any block point.
2. Send it via the `PerasCertDiffusion` mini-protocol.
3. The victim node accepts it unconditionally, stores it, and applies a `PerasWeight` boost (default: 15 block-equivalents) to the adversarial block during chain selection.
4. The victim node's preferred chain shifts to the adversarially boosted fork, diverging from the honest majority chain.

This completely circumvents the Peras quorum requirement (3/4 + 2% safety margin of total stake). The attacker does not need any stake, any committee membership, or any cryptographic key material. The entire purpose of the Peras voting round — to require a supermajority of stake to certify a block — is nullified.

---

### Likelihood Explanation

**Likelihood: High.**

- The vulnerable code path is active in the production `mkHandlers` wiring in `NodeToNode.hs`.
- Any peer that speaks the `PerasCertDiffusion` mini-protocol can trigger it.
- No stake, no keys, and no prior state are required.
- The `PerasCert` serialization format is public and straightforward (CBOR list of round number + block point).
- The only mitigating factor is that Peras is not yet deployed on mainnet; however, the code is in the production diffusion path and will be active when Peras activates.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with full validation that:

1. Verifies the aggregate BLS signature in the certificate against the declared voter set.
2. Checks that the declared voters constitute a quorum (≥ 3/4 + safety margin of total stake) using the stake distribution from the ledger state at the relevant epoch.
3. Verifies VRF eligibility proofs for non-persistent committee members.
4. Checks that the certificate's round number is within the valid acceptance window (`perasCertMaxRounds`).
5. Checks that the boosted block point exists and is on a valid chain.

Until full validation is implemented, the certificate diffusion inbound handler should reject all certificates (return `Left` unconditionally) rather than accept all of them.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start a Peras-enabled node (any era with Peras active).
2. Connect an adversarial peer that speaks `PerasCertDiffusion`.
3. The adversarial peer sends a batch containing:
   ```
   PerasCert { pcCertRound = 999, pcCertBoostedBlock = <point of adversarial fork tip> }
   ```
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{..., vpcCertBoost = PerasWeight 15}`.
5. The certificate is stored via `ChainDB.addPerasCertAsync`.
6. On the next chain selection event, `weightedSelectView` computes `wsvWeightBoost` for the adversarial fork as 15, making it preferred over an honest chain with up to 15 more blocks.
7. The victim node switches to the adversarial fork without any quorum having been reached. [8](#0-7) [9](#0-8) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L41-60)
```haskell
data WeightedSelectView proto = WeightedSelectView
  { wsvBlockNo :: !BlockNo
  -- ^ The 'BlockNo' at the tip of a fragment.
  , wsvWeightBoost :: !PerasWeight
  -- ^ The weight boost of a fragment (w.r.t. a particular anchor).
  , wsvTiebreaker :: TiebreakerView proto
  -- ^ Lazy because it is only needed when 'wsvTotalWeight' is inconclusive.
  }

deriving stock instance Show (TiebreakerView proto) => Show (WeightedSelectView proto)
deriving stock instance Eq (TiebreakerView proto) => Eq (WeightedSelectView proto)

-- TODO: More type safety to prevent people from accidentally comparing
-- 'WeightedSelectView's obtained from fragments with different anchors?
-- Something ST-trick like?

-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-60)
```haskell
-- | Concrete Peras certificates using BLS signatures
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-177)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
