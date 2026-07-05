### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Certificate, Enabling Chain-Selection Weight Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementation of `validatePerasCert` in the `BlockSupportsPeras` typeclass is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or eligibility checks. Because this stub is the active implementation for all block types while Peras is under development, any unprivileged peer can inject a crafted `PerasCert` for an arbitrary block via the Peras object-diffusion mini-protocol. The certificate is accepted as `ValidatedPerasCert`, stored in the `PerasCertDB`, and its weight boost is applied during chain selection — allowing an adversary to make an honest node prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` stub:**

`BlockSupportsPeras` defines a default method `validatePerasCert` that is explicitly marked as a placeholder:

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

This function never inspects the certificate's BLS aggregate signature, never verifies that the claimed voters are actual committee members for the stated round, and never checks that the boosted block is a valid candidate on any chain. It wraps the raw, unverified `cert` directly into `ValidatedPerasCert` and returns `Right`.

**Parallel stub in `implAddCert`:**

The `PerasCertDB` implementation carries the same acknowledged gap:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert :: ...
``` [2](#0-1) 

`implAddCert` accepts a `WithArrivalTime (ValidatedPerasCert blk)` — but the only thing that makes a cert "validated" is the stub above, which never rejects anything.

**Parallel stub in `implAddVote`:**

The same pattern exists for votes:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote perasCfg PerasVoteDbEnv{...} vote = ...
``` [3](#0-2) 

**Attacker-controlled entry path:**

Inbound Peras objects arrive via the object-diffusion mini-protocol. The writer path for certificates calls `validatePerasCert` before storing:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

For certificates the analogous call goes through `validatePerasCert`. Because that function always returns `Right`, a crafted certificate for any block — including one on an adversarial fork — passes "validation" and is stored with its full weight boost.

**Weight boost applied to chain selection:**

The stored `ValidatedPerasCert` contributes `vpcCertBoost` to the `PerasWeightSnapshot` used by `preferAnchoredCandidate` during chain selection:

```haskell
assert (all (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . fst) candidates)
``` [5](#0-4) 

A fraudulent certificate boosting an adversarial block can therefore tip chain selection away from the honest chain.

---

### Impact Explanation

An unprivileged peer sends a single crafted `PerasCert` message claiming to certify a block on an adversarial fork. The receiving node's `validatePerasCert` stub accepts it unconditionally, stores it in `PerasCertDB`, and the resulting weight boost is applied in `chainSelection`. If the boost is large enough (controlled by `perasWeight` in the node's own `PerasCfg`), the node switches to the adversarial chain. This is a **bypass of Peras certificate/signature validation that enables unauthorized certificate acceptance**, matching the Critical impact tier: "Bypass of… certificate/signature validation… that enables unauthorized… certificate acceptance."

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is reachable by any connected peer without authentication. The stub is the active code path for all block types while Peras is under development. No key material, stake, or operator access is required — only the ability to send a well-formed CBOR-encoded `PerasCert` message. The TODO comment and linked issue (`tweag/cardano-peras#120`) confirm the gap is known but not yet closed.

---

### Recommendation

**Short term:** Replace the `validatePerasCert` stub with a guard that rejects all certificates until real validation is implemented — i.e., return `Left PerasValidationErr` unconditionally rather than `Right`. This mirrors the recommendation from the external report: ensure the function fails if the system is not in a state where the operation is permitted (no real validation logic present).

**Long term:** Implement full certificate validation: verify the BLS aggregate signature over `(roundNo, boostedBlock)`, confirm each claimed voter seat index maps to an actual committee member for that round, verify non-persistent voters' VRF eligibility proofs, and check that the boosted block is a known candidate on the node's chain. Apply the same treatment to `validatePerasVote`.

---

### Proof of Concept

1. Connect to a node running the Peras-enabled consensus code as an unprivileged peer.
2. Craft a `PerasCert` (CBOR-encoded per `ToCBOR PerasCert`) with `pcCertRound = <any round>` and `pcCertBoostedBlock = <hash of adversarial block>`.
3. Send it via the Peras object-diffusion mini-protocol.
4. The node calls `validatePerasCert`, which returns `Right ValidatedPerasCert{vpcCert = <crafted cert>, vpcCertBoost = perasWeight params}` without any checks.
5. `implAddCert` stores the cert in `PerasCertDB`; the weight snapshot is updated.
6. On the next `chainSelection` invocation, `preferAnchoredCandidate` applies the fraudulent boost; if the adversarial chain's boosted weight exceeds the honest chain's weight, the node switches to the adversarial chain.

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L109-113)
```haskell
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1128-1132)
```haskell
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
```
