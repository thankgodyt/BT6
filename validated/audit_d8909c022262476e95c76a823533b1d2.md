### Title
Missing Peras Certificate Validation Before Storage Allows Unprivileged Peer to Corrupt Chain-Selection Weights - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The `implAddCert` function in `PerasCertDB/Impl.hs` explicitly defers all non-trivial certificate validation (marked TODO), and the only upstream gate — `validatePerasCert` in `BlockSupportsPeras.hs` — is a degenerate stub that unconditionally returns `Right` for every certificate it receives. An unprivileged peer can therefore inject a crafted `PerasCert` with an arbitrary round number and an arbitrary boosted-block point. The cert is stored in `PerasCertDB`, its boost weight is included in every subsequent `getWeightSnapshot` call, and that snapshot is fed directly into `compareCandidateChains`, causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause 1 — `validatePerasCert` is a no-op stub.**

The `BlockSupportsPeras` instance that covers all block types is explicitly labelled a "degenerate instance … to get things to compile": [1](#0-0) 

The `validatePerasCert` implementation inside that instance always returns `Right` without inspecting the certificate's round number, boosted-block point, or any cryptographic material: [2](#0-1) 

**Root cause 2 — `implAddCert` explicitly defers all non-trivial validation.**

The function that writes a certificate into the `PerasCertDB` carries a developer TODO acknowledging that the required validation logic has not yet been implemented: [3](#0-2) 

The only guard present is a duplicate-round-number check (`Set.member roundNo pcdsCertIds`). No check is made that the boosted block exists on the node's chain, that the round number is plausible relative to the current slot, or that any cryptographic proof is valid.

**Root cause 3 — stored certs directly drive chain selection.**

`implGetWeightSnapshot` iterates over every cert in `pcdsCertsByTicket` and builds a `PerasWeightSnapshot` from their `(boostedBlock, boost)` pairs: [4](#0-3) 

That snapshot is consumed by `readChainComparison` in the BlockFetch client interface, which constructs `compareCandidateChains` used during chain selection: [5](#0-4) 

**Analog to the Holdefi bug.** In Holdefi, `depositPromotionReserve` skips the `isActive` whitelist check, so any address can be passed as a market and fake state is written. Here, `implAddCert` skips all certificate validity checks (the `isActive` equivalent), so any peer-supplied cert is accepted and fake chain-selection weight is written into persistent in-memory state.

---

### Impact Explanation

A peer that can send Peras certificate objects (via the Peras certificate diffusion miniprotocol) can craft a `PerasCert` that:

1. Claims a high round number, making `pcdsLatestCertSeen` point to the attacker's cert.
2. Claims to boost an arbitrary block point — including a block on a weaker or adversarial fork.

Because `getWeightSnapshot` returns these fake boosts to `compareCandidateChains`, the honest node will prefer the adversarially boosted chain over the canonical chain, constituting a **chain-selection safety failure**: the node accepts and follows a non-canonical chain without any legitimate quorum having been reached.

This matches the **High** impact category: *Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.*

---

### Likelihood Explanation

The Peras certificate diffusion miniprotocol is an externally reachable network endpoint. Any peer that connects to the node can send crafted `PerasCert` messages. No stake, key material, or operator privilege is required. The stub `validatePerasCert` and the TODO-gated `implAddCert` are both in production source files, not test or benchmark code. The attack requires only knowledge of the wire format, which is public.

---

### Recommendation

1. **Implement `validatePerasCert` properly.** Replace the degenerate stub with a real implementation that verifies the certificate's cryptographic proof, round number bounds, and boosted-block existence before producing a `ValidatedPerasCert`. [2](#0-1) 

2. **Implement the non-trivial validation in `implAddCert`.** Before writing to `PerasCertDB`, verify that the cert's round number is within the current Peras window and that the boosted block is on the node's current chain (or at least within the volatile suffix). [3](#0-2) 

3. **Apply the same fix to `implAddVote`.** The vote DB carries an identical TODO and the same missing validation path, and votes that accumulate to quorum trigger automatic certificate forging. [6](#0-5) 

---

### Proof of Concept

```
1. Attacker connects to an honest node via the Peras certificate miniprotocol.

2. Attacker constructs a PerasCert:
     pcCertRound      = <current_round + 1>   -- any plausible round
     pcCertBoostedBlock = <point of a block on attacker's fork>

3. Attacker sends the cert to the node.

4. Node calls validatePerasCert (degenerate stub):
     validatePerasCert params cert = Right ValidatedPerasCert{vpcCert=cert, vpcBoost=perasWeight params}
   -- Always succeeds; no cryptographic check performed.

5. Node calls implAddCert with the ValidatedPerasCert.
   -- roundNo not in pcdsCertIds => cert is inserted unconditionally.
   -- pcdsLatestCertSeen updated to attacker's cert.

6. Next call to getWeightSnapshot returns a PerasWeightSnapshot that
   includes (attacker's fork block, perasWeight) as a boosted entry.

7. compareCandidateChains now scores the attacker's fork higher than
   the canonical chain, causing the node to switch to the adversarial fork.
``` [7](#0-6) [2](#0-1)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-201)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/BlockFetch/ClientInterface.hs (L233-241)
```haskell
    readChainComparison :: STM m (WithFingerprint (ChainComparison (HeaderWithTime blk)))
    readChainComparison =
      fmap mkChainComparison <$> getPerasWeightSnapshot chainDB
     where
      mkChainComparison weights =
        ChainComparison
          { plausibleCandidateChain = plausibleCandidateChain weights
          , compareCandidateChains = compareCandidateChains weights
          }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```
