### Title
Unconditional Peras Certificate Acceptance Enables Unauthorized Chain-Selection Weight Injection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally accepts every inbound Peras certificate without any cryptographic or structural verification. Because the `PerasCertDiffusion` mini-protocol is wired up in the node-to-node handler layer and feeds directly into this stub, any unprivileged peer can inject a crafted certificate for an arbitrary block. The accepted certificate carries a `vpcCertBoost :: PerasWeight` that is applied during Peras chain selection, allowing an attacker to boost a non-canonical chain above the honest tip.

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`:**

The only `BlockSupportsPeras` instance in the codebase is a catch-all for all `StandardHash blk` types. Its `validatePerasCert` implementation performs zero verification:

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

The degenerate `PerasCert blk` data type itself carries no cryptographic signature field at all:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

There is no committee membership check, no aggregate signature verification, no quorum check, and no round-validity check. Any `PerasCert` value, regardless of origin, is wrapped in `ValidatedPerasCert` and assigned the full configured `perasWeight`.

**Attacker-controlled entry path — `PerasCertDiffusion` mini-protocol:**

The cert diffusion inbound handler is unconditionally wired up in the production node-to-node handler construction:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [3](#0-2) 

Any peer that successfully negotiates the `PerasCertDiffusion` protocol can push arbitrary `PerasCert` objects. The pool writer calls `validatePerasCert` (the stub above) before storing the result as a `ValidatedPerasCert` in the `ChainDB`. No sender identity check, no committee eligibility check, and no cryptographic proof is required.

**Chain-selection impact:**

`ValidatedPerasCert` carries `vpcCertBoost :: PerasWeight`. The Peras chain-selection logic uses this boost when comparing candidate chain fragments — a certified block gains additional weight beyond its block number, potentially making a shorter or weaker fork preferred over the honest canonical chain. [4](#0-3) 

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `Point blk` as `pcCertBoostedBlock` and any `PerasRoundNo` as `pcCertRound`. The receiving node accepts it unconditionally, stores it as a `ValidatedPerasCert` with the full `perasWeight` boost, and applies that boost during chain selection. If the attacker targets a block on a fork that is slightly behind the honest tip, the injected boost can flip the chain-selection comparison, causing the honest node to roll back to and extend the adversarial fork. This is a **bypass of Peras certificate validation checks enabling unauthorized certificate acceptance and chain-selection manipulation** — matching the "Critical/High" impact tier: bypass of certificate checks that enables unauthorized certificate acceptance, and a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

### Likelihood Explanation

The entry path requires only a standard node-to-node connection; no privileged keys, stake, or operator access are needed. The attacker needs only to:
1. Connect to a target node as a peer.
2. Negotiate the `PerasCertDiffusion` protocol version.
3. Send a `PerasCert` with `pcCertBoostedBlock` pointing to any block the target node holds in its VolatileDB.

The stub is the only `BlockSupportsPeras` instance in the codebase (catch-all for all `StandardHash blk`), so there is no alternative code path that would perform real validation.

### Recommendation

Replace the `validatePerasCert` stub with a real implementation that:
1. Verifies the aggregate BLS/committee signature over `(pcCertRound, pcCertBoostedBlock)`.
2. Checks that the signing committee members are drawn from the correct epoch's stake distribution and that their combined weight meets the quorum threshold.
3. Verifies that `pcCertRound` falls within the expected window relative to the current slot.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled or should reject all inbound certificates, analogous to how the vote diffusion handler currently uses `(pure (PerasVoteStakeDistr mempty))` to reject all votes. [5](#0-4) 

### Proof of Concept

1. Connect to a target node as a peer and negotiate `PerasCertDiffusion`.
2. Observe the target's VolatileDB (via ChainSync) to identify a block `P` on a fork that is `W` blocks behind the honest tip, where `W * blockWeight < perasWeight`.
3. Construct `PerasCert { pcCertRound = r, pcCertBoostedBlock = P }` for any round `r`.
4. Send the cert via the `ObjectDiffusion` protocol.
5. The target node calls `validatePerasCert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
6. The cert is stored in ChainDB. Chain selection now compares the honest tip (no cert boost) against the fork tip (with `perasWeight` boost). If `perasWeight > W * blockWeight`, the node rolls back to and extends the adversarial fork. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
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
            controlMessageSTM
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```
