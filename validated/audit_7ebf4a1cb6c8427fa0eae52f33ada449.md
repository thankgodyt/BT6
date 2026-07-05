### Title
Peras Certificate Validation Bypass via Stub `validatePerasCert` Accepting Any Peer-Supplied Certificate — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` contains a stub `validatePerasCert` that unconditionally returns `Right` for every certificate it receives, performing no cryptographic signature verification whatsoever. Any unprivileged peer connected via the Peras certificate diffusion mini-protocol can inject an arbitrary, forged `PerasCert` that the node will accept as valid, store in the `PerasCertDB`, and use to apply a Peras weight boost during chain selection — potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates. The only instance in the entire codebase is the catch-all default instance:

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
``` [1](#0-0) 

This function ignores the certificate's cryptographic content entirely and returns a `ValidatedPerasCert` carrying the full `perasWeight` boost for any input. There is no other `BlockSupportsPeras` instance anywhere in the repository (confirmed: `grep -r "instance.*BlockSupportsPeras"` returns exactly two lines, both in this file).

The inbound network path that feeds peer-supplied certificates into this function is wired unconditionally in the production node-to-node handler:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      version
      controlMessageSTM
``` [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert` on every inbound certificate before storing it. Because `validatePerasCert` is a no-op stub, every certificate passes. The accepted certificate is then forwarded to `addPerasCertAsync` / `addPerasCertSync`, which stores it in the `PerasCertDB` and triggers chain selection:

```haskell
addPerasCertSync ::
  IOLike m =>
  ChainDB m blk -> WithArrivalTime (ValidatedPerasCert blk) -> m AddPerasCertChainSelOutcome
addPerasCertSync chainDB cert =
  waitPerasCertProcessed =<< addPerasCertAsync chainDB cert
``` [3](#0-2) 

Chain selection now uses Peras weight (block number + weight boost) rather than block number alone:

> "Make the ChainDB aware of the PerasCertDB, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length." [4](#0-3) 

A fraudulent certificate boosting a block on an adversary's fork can therefore tip chain selection in favour of that fork.

For completeness, `validatePerasVote` is also a stub, but the production vote-diffusion handler passes an empty stake distribution (`PerasVoteStakeDistr mempty`), which causes all votes to be rejected at the stake-lookup step — an accidental mitigation that does not apply to the certificate path. [5](#0-4) 

---

### Impact Explanation

When Peras is enabled for an era (controlled by `eraPerasRoundLength` in `EraParams`), a forged certificate accepted via this path grants an attacker-chosen block a `perasWeight` boost in chain selection. The boosted chain can outweigh the honest canonical chain, causing the node to roll back to and adopt the adversary's fork. This is a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**, matching the "High" impact tier. [6](#0-5) 

---

### Likelihood Explanation

Peras is not enabled by default today (`eraPerasRoundLength` defaults to `NoPerasEnabled`), so the weight boost is not applied on current mainnet. However:

1. The Peras cert diffusion mini-protocol is **already wired and active** in the production node-to-node handler — any peer speaking the protocol can send certificates right now.
2. The Peras feature is explicitly planned for production deployment; the CHANGELOG records active integration work across multiple releases.
3. No stake, key material, or privileged access is required — any peer that can establish a node-to-node connection can exploit this.

Likelihood is **Medium** (not yet exploitable on mainnet due to the feature flag, but the vulnerable code path is live and the feature is on a known deployment trajectory).

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature over the certificate's `(roundNo, boostedBlock)` payload against the aggregate public key of the claimed committee members.
2. Verifies each claimed committee member's eligibility (stake threshold, VRF proof for non-persistent members) against the ledger's stake distribution for the relevant epoch.
3. Checks that the certificate's round number is within the acceptable window (not stale, not from the future).

Until a real implementation is ready, the Peras cert diffusion inbound handler should reject all inbound certificates (return a validation error) rather than accept them unconditionally, to prevent the stub from being exploited once Peras is enabled.

---

### Proof of Concept

**Attacker preconditions:** Any node-to-node peer connection; no keys, stake, or privileges required.

**Steps:**

1. Attacker establishes a standard node-to-node connection to the victim node.
2. Attacker constructs a `PerasCert` with:
   - `pcCertRound` = current Peras round number
   - `pcCertBoostedBlock` = the tip of the attacker's private fork
3. Attacker sends this certificate via the `PerasCertDiffusion` mini-protocol.
4. The victim's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert`.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
6. The certificate is stored in `PerasCertDB` and `addPerasCertAsync` triggers chain selection.
7. Chain selection computes `WeightedSelectView` for all candidate chains; the attacker's fork now carries `perasWeight` additional weight.
8. If the attacker's fork is otherwise within `k` blocks of the honest tip, the boosted weight causes the victim to switch to the attacker's fork. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
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
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L625-629)
```haskell
addPerasCertSync ::
  IOLike m =>
  ChainDB m blk -> WithArrivalTime (ValidatedPerasCert blk) -> m AddPerasCertChainSelOutcome
addPerasCertSync chainDB cert =
  waitPerasCertProcessed =<< addPerasCertAsync chainDB cert
```

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/HardFork/History/EraParams.hs (L147-149)
```haskell
  , eraPerasRoundLength :: !(PerasEnabled PerasRoundLength)
  -- ^ Optional, as not every era will be Peras-enabled
  }
```
