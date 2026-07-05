### Title
Peras Certificate Validation Is a No-Op Stub, Allowing Any Peer to Inject Arbitrary Chain-Boosting Certificates — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. Because this instance is the only one wired into the production node-to-node `PerasCertDiffusion` miniprotocol handler, any unprivileged peer can send a crafted `PerasCert` that is accepted, stored in `PerasCertDB`, and applied as a chain-selection boost weight — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must be passed before a certificate received from a peer is stored and used for chain selection: [1](#0-0) 

The only concrete instance in the codebase is the universal stub:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [2](#0-1) 

This stub performs **no** checks whatsoever — no aggregate BLS signature verification, no committee membership check, no VRF eligibility proof, no quorum threshold, no round-number bounds, and no check that the boosted block even exists on any known chain.

The production node-to-node handler wires this stub directly into the inbound `PerasCertDiffusion` miniprotocol:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [3](#0-2) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts` with `validatePerasCert mkPerasParams` as the validation function: [4](#0-3) 

`processCerts` calls `validateCert` on each received certificate and, if it returns `Right`, immediately stores it in the `PerasCertDB` via `addCert`: [5](#0-4) 

`implAddCert` in `PerasCertDB/Impl.hs` also carries its own TODO noting that non-trivial validation logic is still missing: [6](#0-5) 

Once stored, the certificate's boost weight is applied to chain selection via `getWeightSnapshot`, which reads all stored `ValidatedPerasCert` entries and returns their `vpcCertBoost` values: [7](#0-6) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

A peer can craft a `PerasCert` with an arbitrary `pcCertBoostedBlock` (any block point, including one on an adversary-controlled fork) and an arbitrary `pcCertRound`. Because `validatePerasCert` returns `Right` unconditionally, the certificate is stored with a full `perasWeight` boost. Chain selection then applies this boost to the adversary's chosen block, potentially causing the node to switch to a non-canonical chain that it would otherwise reject. This directly undermines the Peras protocol's chain-quality and common-prefix guarantees.

---

### Likelihood Explanation

**High.** The attack requires only a standard peer-to-peer TCP connection to the node's NTN port. No stake, no keys, no special privileges are needed. The `PerasCertDiffusion` miniprotocol is exposed to all connected peers. The attacker simply sends a well-formed CBOR-encoded `PerasCert` message; the stub validation ensures it is accepted every time.

---

### Recommendation

Before the Peras feature is enabled in any production or pre-production environment, `validatePerasCert` must be replaced with a real implementation that:

1. Verifies the aggregate BLS signature over `(electionId, candidate)` against the declared committee members' aggregate verification key.
2. Checks that each declared voter is a legitimate committee member with sufficient stake.
3. Verifies VRF eligibility proofs for non-persistent voters.
4. Confirms that the total voting weight meets the quorum threshold.
5. Validates that `pcCertRound` and `pcCertBoostedBlock` are within protocol-defined bounds.

Until this is done, the `PerasCertDiffusion` miniprotocol should not be enabled on any node that participates in chain selection.

---

### Proof of Concept

The attacker-controlled entry path is:

```
Peer (TCP/NTN) 
  → PerasCertDiffusion miniprotocol (objectDiffusionInbound)
  → makePerasCertPoolWriterFromChainDB
  → processCerts [...] (validatePerasCert mkPerasParams) [...]
  → validatePerasCert: always returns Right ValidatedPerasCert{vpcCertBoost = perasWeight params}
  → implAddCert: stores cert in PerasCertDB unconditionally
  → getWeightSnapshot: returns boost for pcCertBoostedBlock
  → chain selection: prefers the boosted (adversary-chosen) block
```

A minimal crafted certificate:

```haskell
-- Attacker sends this over the PerasCertDiffusion wire protocol:
PerasCert
  { pcCertRound      = PerasRoundNo 1          -- any round
  , pcCertBoostedBlock = adversaryForkTipPoint  -- any block point
  }
```

`validatePerasCert mkPerasParams cert` returns:

```haskell
Right ValidatedPerasCert
  { vpcCert      = cert                  -- the crafted cert, unmodified
  , vpcCertBoost = perasWeight mkPerasParams  -- full boost applied
  }
``` [8](#0-7) 

The cert is then stored and its boost weight influences chain selection, with no cryptographic evidence that any committee member ever voted for the boosted block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```
