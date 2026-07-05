### Title
`validatePerasCert` and `validatePerasVote` Perform No Cryptographic Verification, Allowing Any Peer to Inject Arbitrary Peras Certificates and Votes That Corrupt Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` (accepts every certificate with zero checks) and `validatePerasVote` as a pure stake-distribution lookup that ignores the cryptographic signature and all attacker-controlled fields (`pvVoteBlock`, `pvVoteRound`). Because these are the only implementations wired into the production `makePerasCertPoolWriterFromChainDB` and `makePerasVotePoolWriterFromChainDB` writers, any unprivileged peer can inject certificates or votes for arbitrary blocks, triggering chain-selection weight boosts for attacker-chosen points and potentially causing an honest node to prefer a non-canonical chain.

### Finding Description

**Root cause — the only `BlockSupportsPeras` instance:**

`grep` confirms there is exactly one `instance … BlockSupportsPeras` in the entire repository, declared as a catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

**`validatePerasCert` — unconditional `Right`:**

```haskell
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [2](#0-1) 

Every `PerasCert` received from any peer — regardless of its `pcCertBoostedBlock` or `pcCertRound` — is stamped `ValidatedPerasCert` and forwarded to `addPerasCertAsync`, which the `ChainDB` API documents as: *"If this leads to a fork to be weightier than our current selection, this will trigger a fork switch."* [3](#0-2) 

**`validatePerasVote` — signature and field values ignored:**

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise = Left PerasValidationErr
``` [4](#0-3) 

`lookupPerasVoteStake` only checks `pvVoteVoterId` against the stake distribution map; it never inspects `pvVoteBlock`, `pvVoteRound`, or the BLS signature (`pvSignature`). [5](#0-4) 

**Production wiring — both writers call these stubs directly:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validator: [6](#0-5) 

`makePerasVotePoolWriterFromChainDB` passes `\vote -> … pure $ validatePerasVote mkPerasParams sd vote`: [7](#0-6) 

**Downstream cascade — quorum and chain selection:**

Accepted votes flow into `updatePerasRoundVoteStates`, which accumulates stake per `(pvVoteRound, pvVoteBlock)` target. When the attacker-supplied stake total crosses the quorum threshold, `forgePerasCert` is called and the resulting `ValidatedPerasCert` is inserted via `addPerasCertAsync`, boosting the attacker-chosen block in chain selection. [8](#0-7) 

`processCerts` deduplicates only by round number, so one certificate per round per peer is sufficient to inject a boost: [9](#0-8) 

### Impact Explanation

**Certificate path (Critical):** A single peer connection is sufficient. The attacker sends one `PerasCert` with `pcCertBoostedBlock` set to any block point. `validatePerasCert` returns `Right` unconditionally. The certificate is stored and `addPerasCertAsync` triggers a chain-selection re-evaluation that applies a `perasWeight`-sized boost to the attacker-chosen block. If that block is on a fork, the node may switch away from the canonical chain — a chain-selection safety failure caused by a single unauthenticated network message.

**Vote path (High):** Pool IDs are public on-chain data. An attacker enumerates enough pool IDs from the stake distribution, constructs votes with arbitrary `pvVoteBlock` and `pvVoteRound` (no valid BLS signature required), and sends them until the accumulated stake exceeds the quorum threshold. This forges a certificate for an attacker-chosen block, with the same chain-selection consequence as above.

Both paths match the allowed impact scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

The certificate path requires only a single peer connection and one well-formed CBOR-encoded `PerasCert` message — no keys, no stake, no cryptographic work. The vote path requires knowledge of pool IDs (fully public) and sending enough messages to exceed the quorum threshold, which is feasible for any peer that can sustain a connection. Both paths are reachable from the ObjectDiffusion mini-protocol without any privileged access.

### Recommendation

1. **Implement real `validatePerasCert`:** Verify the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's aggregate verification key, and check that `pcCertRound` falls within the acceptable window. The cryptographic primitives already exist in `Ouroboros.Consensus.Peras.Crypto.BLS` and `Ouroboros.Consensus.Committee.WFALS.implVerifyCert`.

2. **Implement real `validatePerasVote`:** Call `verifyVoteSignature` (already implemented in `PerasBLSCrypto`) to check the BLS signature over `(pvVoteRound, pvVoteBlock)`, verify the VRF eligibility proof for non-persistent members, and confirm `pvVoteRound` is within the current acceptable window.

3. **Remove the catch-all instance:** Replace the `instance StandardHash blk => BlockSupportsPeras blk` stub with a proper Cardano-specific instance that wires in the WFALS/EveryoneVotes committee verification logic already present in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes`.

### Proof of Concept

**Certificate injection (single message):**

1. Connect to a target node's ObjectDiffusion endpoint.
2. Construct a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = <any fork tip point>`.
3. Send it via the cert diffusion mini-protocol.
4. `makePerasCertPoolWriterFromChainDB` calls `processCerts`, which calls `validatePerasCert mkPerasParams cert` → always `Right`.
5. `addPerasCertAsync` is called; the ChainDB applies a `perasWeight` boost to the fork tip.
6. If the fork tip's total weight (chain weight + boost) exceeds the canonical tip's weight, the node switches chains.

**Vote injection (quorum accumulation):**

1. Enumerate pool IDs from the public stake distribution snapshot.
2. For each pool ID, construct a `PerasVote` with `pvVoteVoterId = <pool id>`, `pvVoteBlock = <target fork block>`, `pvVoteRound = <current round>`, and any bytes for `pvSignature`.
3. Send votes until `updatePerasRoundVoteStates` accumulates stake above the quorum threshold.
4. `forgePerasCert` is called internally, producing a `ValidatedPerasCert` for the fork block.
5. `addPerasCertAsync` triggers a chain-selection fork switch as above.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L353-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```
