### Title
Unconditional Peras Certificate Acceptance Allows Unprivileged Peer to Inject Arbitrary Chain-Selection Weight Boosts — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic verification of voter eligibility or signatures. This function is wired directly into the live `hPerasCertDiffusionClient` network handler. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as `pcCertBoostedBlock`; the node will accept it as a `ValidatedPerasCert` with full weight boost and feed it into chain selection, potentially causing the node to prefer a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub in the production instance.**

The universal `BlockSupportsPeras` instance (the only one that exists) is explicitly labelled a "degenerate instance for all blks to get things to compile":

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

The function ignores every field of `cert` and returns a fully-weighted `ValidatedPerasCert` unconditionally. There is no check on the claimed `pcCertBoostedBlock`, no verification of voter eligibility, and no signature check.

**Attacker-controlled entry path — the production NTN handler.**

`validatePerasCert mkPerasParams` is passed as the `validateCert` callback inside `makePerasCertPoolWriterFromChainDB`, which is the `ObjectPoolWriter` handed to `objectDiffusionInbound` for the `hPerasCertDiffusionClient` handler:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

Inside `makePerasCertPoolWriterFromChainDB`, the writer calls `processCerts` with `validatePerasCert mkPerasParams` as the validator:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on every inbound cert and, if all pass (which they always do), calls `addCert` — i.e., `ChainDB.addPerasCertAsync` — for each one:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

`addPerasCertAsync` enqueues the cert for chain selection, where it contributes a `perasWeight`-sized boost to the block named in `pcCertBoostedBlock`:

```haskell
addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
-- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
-- be weightier than our current selection, this will trigger a fork switch.
``` [5](#0-4) 

**Analog to the external report.**

In the Aave Lens finding, `processFollow(follower, ...)` used an attacker-supplied `follower` address as the `from` in `transferFrom` without verifying it equalled `msg.sender`. Here, `validatePerasCert` uses the attacker-supplied `pcCertBoostedBlock` as the target of a chain-selection weight boost without verifying any cryptographic proof that the claimed voters actually signed for that block. In both cases, an externally-supplied identity/target is consumed by a privileged operation with no verification.

---

### Impact Explanation

**Classification: High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer that has already propagated a valid (but minority) fork block to the target node can follow up with a crafted `PerasCert` naming that block as `pcCertBoostedBlock`. The node will:

1. Accept the cert unconditionally (no signature check).
2. Store it as a `ValidatedPerasCert` with full `perasWeight` boost.
3. Trigger chain selection, which now sees the attacker's fork block as heavier than the canonical tip.
4. Switch to the attacker's fork.

Because the Peras weight boost is designed to be decisive (it is the entire point of the Peras protocol — to make certified blocks strongly preferred), a single crafted cert is sufficient to flip chain selection. The attacker does not need stake, keys, or any privileged access; they only need a TCP connection to the target node.

---

### Likelihood Explanation

The `hPerasCertDiffusionClient` handler is registered unconditionally in the production NTN handler record and is negotiated whenever the peer supports the corresponding `NodeToNodeVersion`. Any peer that can open a connection and negotiate the Peras cert diffusion mini-protocol can send a crafted cert. No stake, no keys, no prior relationship is required.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies that the set of claimed voters in the cert are eligible members of the voting committee for the cert's round (using the ledger stake distribution and committee selection logic already present in `Committee.WFALS` / `Committee.EveryoneVotes`).
2. Verifies the aggregate vote signature over `(electionId, pcCertBoostedBlock)` using the voters' aggregated verification keys (mirroring `implVerifyCert` in `Committee.WFALS`).
3. Verifies that the total weight of the claimed voters meets the quorum threshold.

Until this is done, the `hPerasCertDiffusionClient` handler should either be disabled (not negotiated) or should reject all inbound certs rather than accepting them unconditionally.

---

### Proof of Concept

**Setup**: Node N is on the canonical chain with tip block B_canonical. Attacker A has propagated a competing fork block B_fork to N via normal BlockFetch (B_fork passes all existing header/block validation).

**Attack**:

1. A opens a connection to N and negotiates the Peras cert diffusion mini-protocol.
2. A sends a single `PerasCert { pcCertRound = r, pcCertBoostedBlock = point(B_fork) }`.
3. N's `hPerasCertDiffusionClient` calls `processVotes` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
4. N calls `ChainDB.addPerasCertAsync` with the validated cert.
5. Chain selection runs; B_fork now has `perasWeight` extra weight. If `perasWeight` exceeds the length difference between the canonical chain and the fork, N switches to B_fork.
6. N is now on the attacker's fork.

The attacker needs no stake, no keys, and no prior relationship with N. The only precondition is that B_fork is already in N's VolatileDB (achievable via normal block diffusion). [6](#0-5) [7](#0-6) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-185)
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

data PerasCertInboundException
  = forall blk. PerasCertValidationError [PerasValidationErr blk]

deriving instance Show PerasCertInboundException

instance Exception PerasCertInboundException

-- | Process a batch of inbound Peras certificates received from a peer.
--
-- Certificates whose round number is already present in the database (as
-- determined by @alreadyInDbSTM@) are silently skipped. The remaining
-- certificates are validated; if /any/ certificate in the batch fails
-- validation, the entire batch is rejected by throwing a
-- 'PerasCertInboundException' (which should make us disconnect from the distant
-- peer, see 'withPeer' bracket function from `ouroboros-network`). Otherwise,
-- each valid certificate is timestamped with the current wall-clock time and
-- added to the database via @addCert@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
