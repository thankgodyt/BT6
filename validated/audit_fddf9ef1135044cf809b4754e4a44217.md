### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates, Enabling Unauthorized Chain-Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate, regardless of content. This stub is wired directly into the production peer-to-peer certificate diffusion path. Any unprivileged peer can send a crafted `PerasCert` targeting an arbitrary block, which will pass validation and be inserted into the `PerasCertDB`, granting that block a Peras weight boost in chain selection.

---

### Finding Description

The `BlockSupportsPeras` instance defined for all `StandardHash blk` types implements `validatePerasCert` as a no-op that always succeeds:

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

This stub is the **only** validation gate before a certificate is accepted into the node's `PerasCertDB`. The production network handler for inbound Peras certificates, `makePerasCertPoolWriterFromChainDB`, calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` partitions the batch into valid/invalid using this validator and adds all "valid" certificates to the chain DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

This handler is registered as `hPerasCertDiffusionClient` in the live node-to-node protocol stack: [4](#0-3) 

Once a certificate is accepted, it is stored in the `PerasCertDB` and used by chain selection to apply a weight boost (`perasWeight = PerasWeight 15` from `mkPerasParams`) to the boosted block: [5](#0-4) 

The `PerasParams` used for validation is the hardcoded `mkPerasParams` default, not any chain-derived configuration: [6](#0-5) 

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

A Peras certificate grants a configurable weight boost (`perasWeight`) to the block it references. Chain selection uses these boosts when comparing candidate chains via `getPerasWeightSnapshot`. Because `validatePerasCert` never rejects any certificate, an attacker can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block on a non-canonical fork.
2. Send it to an honest node over the Peras certificate diffusion mini-protocol.
3. The certificate passes validation unconditionally and is stored in the `PerasCertDB`.
4. Chain selection now treats the attacker's chosen block as having a weight boost of 15, potentially making a shorter or weaker fork appear heavier than the canonical chain.
5. The honest node switches to the attacker's fork, diverging from the canonical chain.

No cryptographic proof, committee membership credential, quorum evidence, or stake-weighted signature is required. The `PerasCert` data type only contains a round number and a block point — both freely chosen by the attacker. [7](#0-6) 

---

### Likelihood Explanation

**Likelihood: High.**

The attack path is direct and requires no special privileges:

- The Peras certificate diffusion client (`hPerasCertDiffusionClient`) is active in the production node-to-node protocol stack for any peer connection.
- The `PerasCert` wire format is simple (round number + block point) and fully documented.
- No cryptographic material is needed — the stub accepts any certificate unconditionally.
- The attacker only needs to establish a standard peer connection to a target node.

The only limiting factor is that Peras must be enabled on the network. The infrastructure is already wired into the production diffusion layer, and the `eraPerasRoundLength` field in `EraParams` controls activation per era. [8](#0-7) 

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validator that checks:

1. **Committee membership**: The certificate must be signed/endorsed by a quorum of eligible committee members for the given round, verified against the stake snapshot for that round.
2. **Cryptographic signatures**: Each contributing vote must carry a valid VRF/KES or equivalent signature from the claimed voter.
3. **Round validity**: The certificate's round number must be within the valid window relative to the current chain tip.
4. **Boosted block existence**: `pcCertBoostedBlock` must reference a block that is actually present in the node's chain fragment.

Until real validation is implemented, the `hPerasCertDiffusionClient` handler should either be disabled or should reject all inbound certificates to prevent unauthorized chain-selection manipulation.

---

### Proof of Concept

```
Attacker node A connects to honest node H as a standard peer.

1. A constructs a PerasCert:
     pcCertRound       = <any round number, e.g. current round>
     pcCertBoostedBlock = <Point of a block on attacker's preferred fork F>

2. A sends the PerasCert to H via the Peras certificate diffusion mini-protocol
   (hPerasCertDiffusionClient / objectDiffusionInbound).

3. H calls processCerts [...] (validatePerasCert mkPerasParams) [...]:
     validatePerasCert mkPerasParams cert
     -- always returns: Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })

4. H stores the certificate in its PerasCertDB and updates its PerasWeightSnapshot,
   granting fork F a weight boost of 15.

5. H's chain selection now prefers fork F over the canonical chain C if
   weight(F) + 15 > weight(C), causing H to switch to F.

6. H is now on a non-canonical fork, diverging from the honest network.
```

The root cause is at: [9](#0-8) 

The reachable production entry point is: [10](#0-9)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-443)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
  , getLatestPerasCertSeen :: STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ Get the latest Peras certificate that has been seen by this node.
  , getLatestPerasCertOnChainRound :: STM m (Maybe PerasRoundNo)
  -- ^ Get the round number of the latest Peras certificate on the currently
  -- preferred chain.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L137-177)
```haskell
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L142-149)
```haskell
data EraParams = EraParams
  { eraEpochSize :: !EpochSize
  , eraSlotLength :: !SlotLength
  , eraSafeZone :: !SafeZone
  , eraGenesisWin :: !GenesisWindow
  , eraPerasRoundLength :: !(PerasEnabled PerasRoundLength)
  -- ^ Optional, as not every era will be Peras-enabled
  }
```
