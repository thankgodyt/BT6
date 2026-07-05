### Title
Unconditional Peras Certificate Acceptance Inflates Chain Weight, Enabling Adversarial Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` is a stub that unconditionally accepts every inbound Peras certificate and assigns it the full configured weight boost. Because this is the only instance wired into the production object-diffusion pipeline, any unprivileged peer can send a crafted certificate that boosts an arbitrary block, inflating the `PerasWeightSnapshot` used by chain selection and causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a certificate before it is stored and its weight boost is applied to chain selection. The sole production instance — a universal `instance StandardHash blk => BlockSupportsPeras blk` — implements this gate as a stub:

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

This stub always returns `Right`, assigning the full `perasWeight params` boost to every certificate regardless of its cryptographic validity, round number plausibility, or committee membership. The `PerasCert` data type in this instance carries only `pcCertRound` and `pcCertBoostedBlock` — no signature field — so there is nothing to check even if the code tried. [2](#0-1) 

The production inbound path in `processCerts` calls exactly this stub:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

Every certificate that passes the trivial round-number deduplication check is timestamped and forwarded to `addPerasCertAsync`, which stores it in the `PerasCertDB`. [4](#0-3) 

`implGetWeightSnapshot` then materialises a `PerasWeightSnapshot` from every stored certificate, mapping each boosted block point to its accumulated weight: [5](#0-4) 

`chainSelectionForBlock` reads this snapshot atomically and passes it into every candidate comparison: [6](#0-5) 

`wsvTotalWeight` adds the accumulated boost to the block number when comparing two chains: [7](#0-6) 

Because the boost is never validated, an adversary can inject an arbitrarily large boost for any block point, making chain selection prefer a shorter or otherwise non-canonical chain.

**Analogy to the Stargate report:** `redeemSend` increases credit based on rewards without decreasing it for fees, producing an inflated credit balance that corrupts downstream availability calculations. Here, `validatePerasCert` increases the chain-weight balance for every received certificate without ever subtracting for invalidity, producing an inflated `PerasWeightSnapshot` that corrupts downstream chain-selection decisions.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` that boosts a block on a shorter or adversarially-controlled fork. The honest node's chain selection will compute a higher `wsvTotalWeight` for that fork and switch to it, abandoning the canonical chain. Because `takeVolatileSuffix` also uses the weight snapshot to determine the immutability boundary, a sufficiently large injected boost can additionally shrink the volatile suffix, causing blocks that should still be rollback-eligible to be treated as immutable prematurely.

This satisfies the **High** impact criterion: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

It also satisfies: *"Bypass of … certificate … validation … that enables unauthorized … certificate acceptance."*

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a standard peer-to-peer channel. Any connected peer can send a `PerasCert` message. No stake, key material, or privileged access is required. The only existing guard — round-number deduplication — is trivially bypassed by using a fresh round number. The attack is therefore reachable by any node that can establish a connection, making likelihood **High** once the Peras protocol is active on a network running this code.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with one that performs the full cryptographic and semantic checks required by the Peras specification before a certificate is accepted and its weight boost is applied. At minimum this must include:

1. Verifying the aggregate BLS signature over the election identifier and boosted block hash against the claimed committee members' public keys.
2. Checking that the claimed voters are eligible committee members for the stated round (VRF-based sortition).
3. Verifying that the total stake of the signers exceeds the quorum threshold.
4. Checking that the boosted block point is plausible (e.g., not in the future, not older than the immutable tip).

Until the full validation is implemented, the weight boost from peer-supplied certificates should not be applied to chain selection.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start two nodes, A (honest) and B (adversary), connected to each other.
2. Node A has a canonical chain of length N.
3. Node B has a shorter fork of length N-5 ending at block `X`.
4. Node B crafts a `PerasCert` with `pcCertRound = freshRound` and `pcCertBoostedBlock = blockPoint X`, where `perasWeight` is configured to be, say, 10.
5. Node B sends this certificate to Node A via the object-diffusion mini-protocol.
6. Node A's `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
7. The cert is stored; `implGetWeightSnapshot` now returns a snapshot with `weightBoostOfPoint snap (blockPoint X) = PerasWeight 10`.
8. When Node B's fork is offered to Node A via ChainSync, `wsvTotalWeight` for B's fork = `(N-5) + 10 = N+5`, which exceeds A's canonical chain weight of `N`.
9. Node A switches to B's shorter, non-canonical fork. [8](#0-7) [9](#0-8) [5](#0-4) [10](#0-9)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L629-634)
```haskell
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-88)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT

```
