### Title
Peras Certificate Validation Unconditionally Accepts Any Crafted Certificate Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance, which applies to all block types including Cardano blocks, implements `validatePerasCert` to unconditionally return `Right` (success) without performing any cryptographic or semantic validation. An unprivileged peer can send a crafted Peras certificate via the object diffusion miniprotocol; it will pass validation, be stored in the `PerasCertDB`, and inject a weight boost into chain selection — enabling an attacker to make an honest node prefer a non-canonical chain.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the degenerate catch-all instance is declared at line 320:

```haskell
instance StandardHash blk => BlockSupportsPeras blk where
```

Its `validatePerasCert` implementation at lines 350–358 unconditionally returns `Right` regardless of the certificate's content:

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

No signature is verified, no round number is checked, and no boosted block validity is confirmed. The certificate is unconditionally wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost.

Similarly, `validatePerasVote` at lines 363–371 only checks whether the voter ID appears in the stake distribution; it performs no cryptographic signature verification over the vote content:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

The `implAddCert` function in `PerasCertDB/Impl.hs` at line 167 carries the same admission: `"TODO: we will need to update this method with non-trivial validation logic"`. [3](#0-2) 

The attacker-controlled entry path is the Peras object diffusion inbound miniprotocol. Received certificates are passed to `validatePerasCert` before being stored. Because the degenerate instance always returns `Right`, any crafted certificate clears the validation gate. [4](#0-3) 

Chain selection reads weight snapshots from `PerasCertDB` via `getWeightSnapshot`/`implGetWeightSnapshot`, and the `preferAnchoredCandidate` logic in `ChainSel` uses those weights when comparing candidate chains. [5](#0-4) 

---

### Impact Explanation

An unprivileged peer can inject a `PerasCert` for any block it chooses — including a block on a weaker or adversarial fork — and the certificate will be accepted and stored with a full weight boost. Because Peras weight boosts directly influence `preferAnchoredCandidate` during chain selection, the attacker can cause an honest node to prefer a non-canonical chain over the honest chain. This is a bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain-selection manipulation, matching the **Critical** impact tier: "Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."

---

### Likelihood Explanation

The object diffusion inbound miniprotocol for Peras certificates is implemented and reachable from any connecting peer without any privilege requirement. The degenerate instance is the only `BlockSupportsPeras` instance in the repository (the TODO at line 318 confirms no concrete instance exists yet for Cardano blocks). Any peer that speaks the Peras object diffusion protocol can trigger this path. Likelihood is moderate: the Peras protocol is under active development and not yet live on mainnet, but the code compiles and the path is exercised in integration tests. [6](#0-5) 

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that:
1. Verifies the aggregate BLS vote signature against the claimed voters' aggregated verification keys (as implemented in `implVerifyCert` in `Committee/WFALS.hs` and `Committee/EveryoneVotes.hs`).
2. Verifies VRF outputs for non-persistent voters.
3. Checks that the certificate's round number is within the valid window relative to the current chain state.
4. Checks that the boosted block point exists on the node's known chain.

Until a concrete instance is ready, the degenerate instance should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the safe default is rejection rather than unconditional acceptance. [7](#0-6) 

---

### Proof of Concept

1. Connect to a node as a peer via the Peras object diffusion inbound miniprotocol (`ObjectDiffusion.Inbound`).
2. Construct a `PerasCert blk` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on a weaker fork.
3. Send the certificate to the node.
4. The node calls `validatePerasCert params cert` on the degenerate instance, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` unconditionally — no signature, no round check, no block existence check.
5. `implAddCert` stores the certificate in `PerasCertDB`.
6. On the next chain selection cycle, `getWeightSnapshot` returns a snapshot that includes the injected boost for the attacker-chosen block.
7. `preferAnchoredCandidate` in `ChainSel` uses the boosted weight, potentially causing the node to switch to the adversarial fork. [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-210)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-495)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
  WFALSCert electionId candidate voters aggSig -> do
```
