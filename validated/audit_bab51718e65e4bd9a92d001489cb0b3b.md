### Title
Unconditional `validatePerasCert` Stub Allows Unprivileged Peer to Suppress All Peras Voting via `latestCertSeen` Poisoning — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the blanket `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` for every inbound certificate, performing no cryptographic or semantic checks. This stub is wired directly into the production ObjectDiffusion inbound path. An unprivileged peer with zero stake can exploit this to inject a `PerasCert` claiming an arbitrarily large future round number. Because `PerasCertDB.implAddCert` updates `pcdsLatestCertSeen` to whichever certificate carries the highest round number, the injected certificate permanently poisons the node's `latestCertSeen` state. Both Peras voting rules VR-1A and VR-2A then evaluate to `False` for all honest nodes for `IgnoranceRounds` (487) rounds beyond the injected round — suppressing all Peras voting and disabling the finality gadget for that entire window. The attack is directly analogous to the governance hostage-taking vulnerability: just as a low-stake actor activates a dummy proposal to block all governance for a `GRACE_PERIOD`, a zero-stake peer injects a dummy certificate to block all Peras voting for a cooldown window, and the attack can be repeated indefinitely.

---

### Finding Description

**Root cause — unconditional certificate acceptance:** [1](#0-0) 

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

Every `PerasCert` received from any peer is immediately wrapped in `Right (ValidatedPerasCert …)` with no signature check, no committee membership check, no quorum check, and no round-number plausibility check.

**Production inbound path — ObjectDiffusion writer:** [2](#0-1) 

`makePerasCertPoolWriterFromChainDB` calls `processCerts … (validatePerasCert mkPerasParams) …`. The `processCerts` function filters out round numbers already in the DB, then calls `validateCert` on every remaining certificate. Because `validateCert` is the stub above, every novel round number passes. [3](#0-2) 

**`latestCertSeen` update — highest-round-wins:** [4](#0-3) 

```haskell
pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
  Nothing -> Just cert
  Just prev
    | getPerasCertRound cert > getPerasCertRound prev -> Just cert
    | otherwise -> Just prev
```

A certificate for round `N` replaces `latestCertSeen` whenever `N` exceeds the current maximum. An attacker who injects round `1_000_000` immediately becomes the new `latestCertSeen` for every node that receives the certificate via diffusion.

**Voting rules that depend on `latestCertSeen`:**

VR-1A requires the latest certificate seen to be from the *immediately preceding* round: [5](#0-4) 

```haskell
VR1A := vr1a1 :/\: vr1a2
-- vr1a1: currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
```

With `latestCertSeen` poisoned to round `1_000_000`, VR-1A requires `currRoundNo == 1_000_001` — impossible for hundreds of thousands of rounds.

VR-2A requires the latest certificate seen to be at least `IgnoranceRounds` (R = 487) rounds in the past: [6](#0-5) 

```haskell
VR2A := vr2a
-- vr2a: getPerasCertRound (lcsCert cert) + _R :<=: currRoundNo
-- _R = PerasIgnoranceRounds = 487
```

With `latestCertSeen` at round `1_000_000`, VR-2A requires `currRoundNo >= 1_000_487` — also impossible for a very long time.

The combined voting rule is a disjunction: [7](#0-6) 

```haskell
perasVotingRules pvv = perasVR1 pvv :\/: perasVR2 pvv
```

Both branches evaluate to `False`, so `isPerasVotingAllowed` returns `NoVote` for every honest node for the entire window.

**`getLatestCertSeen` is the direct input to voting:** [8](#0-7) 

The API comment explicitly states: *"This field impacts voting directly because having seen a certificate is a precondition for voting in any round except for the very first one."*

**Secondary impact — chain selection manipulation:**

The same injected certificate is also indexed in `pcdsCertsByTicket` and contributes to `getWeightSnapshot`, which feeds directly into chain selection: [9](#0-8) 

An attacker can inject a certificate boosting any block (including a block on a minority fork), granting it `perasWeight = 15` extra block-lengths of chain weight. This can cause honest nodes to prefer a non-canonical chain. [10](#0-9) 

---

### Impact Explanation

**Primary (High — Peras voting/certificate check bypass):** An unprivileged peer with zero stake can permanently suppress all Peras voting across the network for `IgnoranceRounds` (487) rounds × `perasRoundLength` (90 slots) = ~43,830 slots (~12 hours) per injected certificate. By injecting a new certificate just before the window expires, the attacker can maintain the suppression indefinitely. The Peras finality gadget is completely disabled; the chain falls back to pure Praos security, losing all settlement guarantees that Peras is designed to provide.

**Secondary (High — chain selection):** The same zero-stake peer can inject a certificate boosting any block, granting it 15 extra block-lengths of weight in chain selection. This can cause honest nodes to switch to a non-canonical or adversarially-controlled fork, constituting a chain selection error triggered by an unprivileged peer.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol is reachable by any peer that can establish a connection to the node. No stake, no key material, and no prior knowledge beyond the protocol wire format is required. The attacker only needs to send a single `PerasCert` message with an arbitrarily large `pcCertRound` value. The stub is currently wired into both the `PerasCertDB`-direct path and the `ChainDB` production path, with explicit `TODO` comments acknowledging the missing validation. [11](#0-10) 

---

### Recommendation

1. **Implement real certificate validation** in `validatePerasCert` before the ObjectDiffusion path is enabled in production. At minimum, verify that the certificate's round number is plausible (within a bounded window of the current round), that the boosted block point is known and within the volatile suffix, and that the aggregate BLS signature over the claimed committee members is valid.

2. **Bound accepted round numbers** in `processCerts`: reject any certificate whose `pcCertRound` exceeds `currRound + maxFutureRounds` for a small constant, preventing far-future poisoning of `latestCertSeen` regardless of signature validity.

3. **Do not update `pcdsLatestCertSeen` unconditionally** on insertion. Gate the update on the certificate passing full validation, including a plausibility check on the round number relative to the node's current view of the chain.

---

### Proof of Concept

```
1. Attacker connects to an honest node via the ObjectDiffusion mini-protocol.

2. Attacker sends a PerasCert batch containing one certificate:
     PerasCert { pcCertRound = PerasRoundNo 1_000_000
               , pcCertBoostedBlock = <any valid-looking Point> }

3. processCerts (ObjectPool/PerasCert.hs:164) calls
     validatePerasCert mkPerasParams cert
   which unconditionally returns
     Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 15 })

4. implAddCert (PerasCertDB/Impl.hs:174) stores the certificate and sets
     pcdsLatestCertSeen = Just (WithArrivalTime now validatedCert)
   because 1_000_000 > any previous latestCertSeen round.

5. Every honest node that receives this certificate (via diffusion) now has
     latestCertSeen = round 1_000_000.

6. For any current round R << 1_000_000:
     VR-1A: R == 1_000_001  →  False
     VR-2A: 1_000_000 + 487 <= R  →  False
     isPerasVotingAllowed → NoVote

7. No honest node votes for ~1_000_387 - R rounds.

8. When R approaches 1_000_387, attacker repeats step 2 with
     pcCertRound = PerasRoundNo 2_000_000, extending the lockout indefinitely.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L184-188)
```haskell
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L139-165)
```haskell
    VR1A := vr1a1 :/\: vr1a2
   where
    -- The latest certificate seen is from the previous round
    vr1a1 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          currRoundNo :==: getPerasCertRound (lcsCert cert) + 1
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0

    -- The latest certificate seen was received within X slots from the start
    -- of its round
    vr1a2 =
      case latestCertSeen of
        -- We have seen a certificate ==> check its arrival time
        NotOrigin cert ->
          lcsArrivalSlot cert :<=: lcsRoundStartSlot cert + _X
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True

    _X =
      SlotNo $
        unPerasCertArrivalThreshold $
          perasCertArrivalThreshold perasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L202-218)
```haskell
    VR2A := vr2a
   where
    vr2a =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          getPerasCertRound (lcsCert cert) + _R :<=: currRoundNo
        -- We have never seen a certificate ==> check if we are recovering from
        -- an initial cooldown after having initially failed to reach a quorum
        Origin ->
          _R :<=: currRoundNo

    _R =
      PerasRoundNo $
        unPerasIgnoranceRounds $
          perasIgnoranceRounds $
            perasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L286-291)
```haskell
perasVotingRules ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVotingRules pvv =
  perasVR1 pvv :\/: perasVR2 pvv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
