### Title
Unconditional Peras Certificate Acceptance and Signature-Free Vote Validation Allow Unauthorized Chain-Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` default instance in `SupportsPeras.hs` implements `validatePerasCert` as an unconditional `Right` (accepts every certificate without any check) and implements `validatePerasVote` with only a stake-distribution membership lookup — no cryptographic signature field exists on `PerasVote` at all. Both functions are called on the live NTN inbound path (`processCerts` / `processVotes`). An unprivileged peer can therefore inject a crafted `PerasCert` for any round and any block, or forge votes attributed to any registered voter, causing the receiving node to boost an attacker-chosen block's chain weight and diverge from the honest chain.

---

### Finding Description

**Root cause 1 — `validatePerasCert` is unconditionally `Right`** [1](#0-0) 

```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

Every `PerasCert` received from any peer is immediately wrapped in `ValidatedPerasCert` and returned as valid. No round-number bounds check, no quorum proof, no aggregate-signature verification.

**Root cause 2 — `PerasVote` carries no signature; `validatePerasVote` only checks stake-distribution membership** [2](#0-1) 

```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound  :: PerasRoundNo
    , pvVoteBlock  :: Point blk
    , pvVoteVoterId :: PerasVoterId   -- no signature field
    }

  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
```

`lookupPerasVoteStake` only checks whether `pvVoteVoterId` is a key in the stake-distribution map: [3](#0-2) 

There is no field to carry a BLS/VRF/KES proof, and no call to any signature-verification primitive. Any peer that knows a registered voter's `PerasVoterId` (a public key hash, visible on-chain) can craft a `PerasVote` that passes validation.

**Inbound processing path — `processCerts` and `processVotes`**

Both functions are called directly from the NTN handler: [4](#0-3) [5](#0-4) 

`processCerts` calls `validateCert` (= `validatePerasCert`) and, on success, calls `addCert` which routes to `ChainDB.addPerasCertAsync`. `processVotes` calls `validateVote` (= `validatePerasVote`) and, on success, calls `addVote` which routes to `ChainDB.addPerasVoteWithAsyncCertHandling`. Both are wired into the live NTN application in `NodeToNode.hs`: [6](#0-5) 

**Note on the current empty stake distribution**: The NTN handler currently passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, which causes all votes to fail the membership check. This is an acknowledged placeholder (the comment says "the empty stake distribution will cause all votes to be considered invalid"). Once the real stake distribution is wired in — the stated next step — the signature-free vote path becomes fully exploitable. The certificate path is exploitable today regardless, because `validatePerasCert` ignores the stake distribution entirely.

---

### Impact Explanation

**Severity: Critical** — matches "Bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance."

- **Certificate injection**: A single unprivileged peer can send a `PerasCert{pcCertRound = r, pcCertBoostedBlock = p}` for any round `r` and any block point `p`. The receiving node accepts it unconditionally, stores it via `addPerasCertAsync`, and the Peras weight boost is applied to block `p` during chain selection. By choosing `p` to be an attacker-controlled or weaker fork tip, the attacker causes the honest node to prefer a non-canonical chain, breaking chain-selection safety.

- **Vote forgery (once stake distribution is live)**: An attacker who knows any registered voter's `PerasVoterId` (public information) can submit enough forged votes to manufacture a quorum for an arbitrary block, triggering automatic certificate forging inside `implAddVote` / `updatePerasRoundVoteStates`, with the same chain-selection consequence.

Both impacts are irreversible within the current selection window: once a certificate is stored and a chain-weight boost applied, the node's selection may switch to the attacker's fork.

---

### Likelihood Explanation

- **Certificate path**: Exploitable today by any NTN peer. No stake, no key material, no prior relationship required. The attacker only needs to open a standard NTN connection and send a CBOR-encoded `PerasCert` over the Peras cert diffusion mini-protocol.
- **Vote path**: Exploitable as soon as the real stake distribution is plumbed in (the TODO is the only barrier). Voter IDs are public key hashes visible in the ledger state, so no secret knowledge is needed.

---

### Recommendation

1. **`validatePerasCert`**: Implement aggregate-signature verification over the claimed quorum of voters before returning `Right`. The `Committee.Class` abstraction already defines `verifyCert` for this purpose.

2. **`validatePerasVote`**: Add a cryptographic signature field to `PerasVote` (e.g., a BLS signature or VRF proof) and verify it inside `validatePerasVote` before accepting the vote. The `Committee.Class` abstraction already defines `verifyVote` for this purpose.

3. Until both checks are implemented, the Peras cert and vote diffusion mini-protocols should not be enabled on any network where chain-selection integrity matters.

---

### Proof of Concept

**Certificate injection (exploitable today):**

1. Connect to a target node as a standard NTN peer.
2. Negotiate the Peras cert diffusion mini-protocol.
3. Send a batch containing one crafted certificate:
   ```
   PerasCert { pcCertRound = <current round>, pcCertBoostedBlock = <attacker fork tip> }
   ```
4. `processCerts` calls `validatePerasCert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
5. The cert is stored via `ChainDB.addPerasCertAsync`; the Peras weight boost is applied to the attacker's fork tip.
6. If the boosted fork is otherwise competitive, the node's chain selection switches to it.

**Vote forgery (exploitable once stake distribution is live):**

1. Read any registered voter's `PerasVoterId` from the ledger state (public).
2. Craft `τ` votes (enough to exceed the quorum threshold) each with `pvVoteVoterId = <known voter>` and `pvVoteBlock = <attacker fork tip>`.
3. Send them via the Peras vote diffusion mini-protocol.
4. `processVotes` → `validatePerasVote` accepts each vote (stake-distribution lookup succeeds, no signature checked).
5. `updatePerasRoundVoteStates` accumulates stake; quorum is reached; `forgePerasCert` is called automatically; the resulting certificate boosts the attacker's fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-371)
```haskell
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-416)
```haskell
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
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
            controlMessageSTM
      , hPerasVoteDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionOutboundTracer tracers))
            (perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasVotePoolReaderFromChainDB $ getChainDB)
            version
```
