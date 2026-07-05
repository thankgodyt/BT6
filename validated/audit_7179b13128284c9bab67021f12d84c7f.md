### Title
Batch Rejection Without Isolation in `processCerts`/`processVotes` Allows Unprivileged Peer to Suppress Valid Peras Certificates and Manipulate Chain Selection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, `PerasVote.hs`)

---

### Summary

Both `processCerts` and `processVotes` in the ObjectDiffusion mini-protocol reject an **entire batch** of inbound Peras certificates/votes if any single item in the batch fails validation. An unprivileged peer can exploit this by including one crafted invalid item alongside legitimate valid items, causing all valid items to be silently discarded. Because Peras certificates directly drive chain selection via weight boosts, suppressing valid certificates allows an adversary to make an honest node prefer a non-canonical or less-secure chain.

---

### Finding Description

`processCerts` in `PerasCert.hs` and `processVotes` in `PerasVote.hs` share the same all-or-nothing batch logic:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->                                    -- valid certs in snd are thrown away
    throw (PerasCertValidationError errs)
``` [1](#0-0) 

The same pattern appears verbatim in `processVotes`: [2](#0-1) 

The code comment explicitly acknowledges the design: *"if any certificate in the batch fails validation, the entire batch is rejected."* [3](#0-2) 

These functions are wired into the production `ObjectPoolWriter` used by the ObjectDiffusion mini-protocol for peer-to-peer certificate and vote diffusion: [4](#0-3) 

For `processVotes`, `validatePerasVote` already returns `Left PerasValidationErr` for any vote whose voter ID is absent from the stake distribution — making the attack immediately exploitable: [5](#0-4) 

For `processCerts`, `validatePerasCert` currently always returns `Right` (stub, TODO), so the cert path is not yet exploitable — but the structural flaw is identical and will become exploitable once real cryptographic validation is wired in. [6](#0-5) 

---

### Impact Explanation

Peras certificates are the direct input to chain selection. The `WeightedSelectView` computes `wsvTotalWeight = blockNo + wsvWeightBoost`, and `preferAnchoredCandidate` switches to a candidate chain when its total weight exceeds the current chain's total weight: [7](#0-6) 

The default `perasWeight` is 15, meaning a single certificate makes a chain appear 15 block-equivalents heavier: [8](#0-7) 

The CHANGELOG confirms this is production chain-selection logic: *"the candidate fragment is now selected based on its Peras weight, instead of its length."* [9](#0-8) 

When an attacker suppresses a certificate that boosts a block on the canonical chain, the victim node's local `PerasWeightSnapshot` does not reflect that boost. `preferAnchoredCandidate` then computes a lower total weight for the canonical chain and may fail to switch to it — or may switch away from it to a competing fork that the attacker controls or benefits from. This is a direct chain-selection manipulation: the node prefers a non-canonical chain beyond the intended Peras security assumptions.

Suppressing votes via `processVotes` has the same downstream effect: if the suppressed votes were the marginal votes needed to reach quorum, no certificate is forged, the boosted block never receives its weight, and chain selection degrades to plain Praos longest-chain — allowing an adversary-controlled shorter fork to be preferred.

**Impact class: High** — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

- Any node participating in the ObjectDiffusion mini-protocol (NodeToNodeV_16+) is a valid attacker. No special privileges, keys, or stake are required.
- For `processVotes`: the attacker only needs to include one vote with a voter ID not in the current stake distribution. This is trivially constructable — the attacker does not need to forge any cryptographic material, only supply a `PerasVote` with an unrecognized `pvVoteVoterId`.
- The attacker can obtain legitimate votes from the network (via the same ObjectDiffusion protocol) and bundle them with the crafted invalid vote in a single batch.
- The attack is a single message, not brute-force or spam.
- For `processCerts`: not exploitable today (stub validation), but the structural flaw is already present and will activate once real cert validation is implemented.

**Likelihood: Medium** — requires participation in the ObjectDiffusion mini-protocol (available to any peer on NodeToNodeV_16+) and trivial construction of one invalid vote.

---

### Recommendation

Replace the all-or-nothing batch rejection with per-item isolation. Valid items should be accepted regardless of whether other items in the same batch are invalid. Invalid items should be individually logged/counted, and the peer should be penalized (or disconnected) only after the valid items have been processed:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (...) certs
  now <- systemTimeCurrent systemTime
  let (errs, validatedCerts) = partitionEithers (validateCert <$> certsNotAlreadyInDb)
  mapM_ (addCert . WithArrivalTime now) validatedCerts   -- accept valid items first
  unless (null errs) $
    throw (PerasCertValidationError errs)                -- then penalize for invalid ones
```

Apply the same fix to `processVotes`. This mirrors the remediation in the reference report: isolate per-item failures so that valid items are never discarded due to a co-located invalid item.

---

### Proof of Concept

**Setup:** A private testnet with Peras enabled. Two honest nodes A and B. Attacker node E connected to A via ObjectDiffusion.

1. Honest nodes produce votes for round R targeting block B on the canonical chain. Votes propagate to E.
2. E constructs a crafted `PerasVote` with a `pvVoteVoterId` that is absent from the current stake distribution (guaranteed `Left` from `validatePerasVote`).
3. E sends a single ObjectDiffusion batch to A containing: the legitimate votes from step 1 **plus** the crafted invalid vote.
4. A calls `processVotes` → `partitionEithers` finds one `Left` → `throw (PerasVoteValidationError ...)` → entire batch discarded.
5. The legitimate votes are never added to A's `PerasVoteDB`. If those votes were the marginal votes needed for quorum, no certificate is forged for round R.
6. Block B on the canonical chain receives no weight boost. A's `PerasWeightSnapshot` shows zero boost for B.
7. A competing fork F (shorter by up to 14 blocks) now has equal or greater `wsvTotalWeight` in A's view. `preferAnchoredCandidate` selects F over the canonical chain.
8. A has been made to prefer a non-canonical chain by an unprivileged peer sending a single crafted message. [10](#0-9) [11](#0-10)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L146-155)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** CHANGELOG.md (L95-97)
```markdown
- Make the `ChainDB` aware of the `PerasCertDB`, and modify the chain selection function accordingly. In practice, it means that the candidate fragment is now selected based on its Peras weight, instead of its length.

  Note that if Peras is disabled (which is the default), there is no observable difference.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-210)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
```
