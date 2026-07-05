### Title
Peras `PerasCertDB` `pcdsLatestCertSeen` Is Purely In-Memory, Enabling VR-1B Voting-Rule Bypass After Node Restart — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs`)

---

### Summary

The `PerasCertDB` implementation stores the `pcdsLatestCertSeen` field — the latest Peras certificate seen by the node — exclusively in a `StrictTVar` with no disk persistence. On every restart the field is reset to `Nothing` (treated as `Origin`). The Peras voting rules (`isPerasVotingAllowed`) use this field as the primary gate for VR-1A and VR-1B. With `latestCertSeen = Origin`, VR-1A always fails for any round > 0, so the node falls through to the VR-2 (cooldown-exit) path, which omits the VR-1B check. A restarted node can therefore cast a vote for a block that does not extend the most recently certified block, bypassing a critical Peras chain-extension safety invariant.

---

### Finding Description

`PerasCertDB.Impl.createDB` always initialises the database from `initialPerasCertDbState`:

```haskell
initialPerasCertDbState :: WithFingerprint (PerasCertDbState blk)
initialPerasCertDbState =
  WithFingerprint
    PerasCertDbState
      { pcdsCertIds        = Set.empty
      , pcdsCertsByTicket  = Map.empty
      , pcdsLastTicketNo   = zeroPerasCertTicketNo
      , pcdsLatestCertSeen = Nothing   -- ← always Nothing on startup
      }
    (Fingerprint 0)
``` [1](#0-0) 

The entire state lives in a `StrictTVar`; there is no `openDB`/snapshot path, no disk read, and no recovery logic:

```haskell
createDB args = do
  pcdbState <- newTVarWithInvariantIO
    (either Just (const Nothing) . invariantForPerasCertDbState)
    initialPerasCertDbState
``` [2](#0-1) 

The `PerasCertDB` is created fresh on every `ChainDB` open:

```haskell
perasCertDB <- PerasCertDB.createDB argsPerasCertDB
perasVoteDB <- PerasVoteDB.createDB argsPerasVoteDB
``` [3](#0-2) 

The API explicitly documents the security relevance of `pcdsLatestCertSeen`:

```haskell
, getLatestCertSeen ::
    STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
-- ^ This field impacts voting directly because having seen a certificate is a
-- precondition for voting in any round except for the very first one
-- (at origin).
``` [4](#0-3) 

`mkPerasVotingView` feeds this value directly into the `PerasVotingView.latestCertSeen` field consumed by `isPerasVotingAllowed`: [5](#0-4) 

With `latestCertSeen = Origin` the voting rules evaluate as follows:

**VR-1A** (`perasVR1A`):
```haskell
Origin -> currRoundNo :==: PerasRoundNo 0
```
→ `False` for every round > 0. [6](#0-5) 

Because VR-1A is `False`, VR-1 (VR-1A ∧ VR-1B) is `False` and **VR-1B is never evaluated**. The node falls through to VR-2:

**VR-2A** (`perasVR2A`):
```haskell
Origin -> _R :<=: currRoundNo
```
→ `True` whenever `currRoundNo ≥ R` (the ignorance period has elapsed since genesis). [7](#0-6) 

If VR-2B is also satisfied (it reads `latestCertOnChain` from the persistent chain state), the node votes via the cooldown-exit path. VR-1B — "the block being voted upon extends the most recently certified one" — is never checked:

```haskell
perasVR1B PerasVotingView{ latestCertSeen } =
  VR1B := vr1b
 where
  vr1b = case latestCertSeen of
    NotOrigin cert -> Bool (lcsCandidateBlockExtendsCert cert)
    Origin         -> Bool True   -- vacuously true, but VR-1 is already False
``` [8](#0-7) 

---

### Impact Explanation

VR-1B is the Peras protocol's chain-extension safety check: it prevents a node from boosting a block that does not descend from the most recently certified block. By losing `pcdsLatestCertSeen` on restart, a node that was in normal (VR-1) operation is silently reclassified as being in cooldown-exit (VR-2) operation. It will cast a vote for whatever block it currently considers best, even if that block does not extend the certified block. If a sufficient fraction of the committee restarts within the same voting round (e.g., after a software upgrade or widespread crash), the aggregate stake of their incorrectly cast votes can reach quorum, producing a certificate for a block that violates the chain-extension invariant. This is a bypass of a Peras voting check that enables unauthorized certificate acceptance — matching the "Critical/High: bypass of Peras voting checks" category in the allowed impact scope.

---

### Likelihood Explanation

Node restarts are routine operational events (rolling upgrades, OOM kills, power outages). The `PerasCertDB` has no persistence layer at all — every restart unconditionally resets `pcdsLatestCertSeen` to `Nothing`. The vulnerability window is the interval between restart and the moment the node re-receives the latest certificate from peers. In a large stake pool operator cluster performing a coordinated upgrade, many nodes may be in this window simultaneously. No attacker capability beyond having a competing chain tip is required; the unsafe vote is cast by the honest node itself.

---

### Recommendation

Persist `pcdsLatestCertSeen` (and the full `PerasCertDbState`) to disk using the same snapshot/recovery pattern already used by `LedgerDB`. On startup, load the most recent valid snapshot before evaluating any voting rules. As a defence-in-depth measure, add a startup guard that suppresses voting until the node has either loaded a persisted cert state or has been connected to peers long enough to have received the latest certificate (analogous to the Genesis State Machine's sync guard).

---

### Proof of Concept

```
1. Node N is in round R_n (R_n > 0, R_n ≥ perasIgnoranceRounds).
   pcdsLatestCertSeen = Just cert_{R_n - 1}
   (cert_{R_n-1} boosts block B_cert on the canonical chain)

2. Node N restarts (software upgrade / crash).
   PerasCertDB.createDB → pcdsLatestCertSeen = Nothing

3. Adversary A has a competing tip B_adv that does NOT extend B_cert.

4. Node N evaluates isPerasVotingAllowed for round R_n:
   - latestCertSeen = Origin
   - VR-1A: R_n == 0  → False  (VR-1 short-circuits; VR-1B never checked)
   - VR-2A: R ≤ R_n   → True
   - VR-2B: (depends on latestCertOnChain, which is persistent) → True

5. Node N votes for B_adv via VR-2, bypassing VR-1B.
   The vote is valid on the wire (correct signature, correct round).

6. If enough committee members are in the same state, quorum is reached
   for B_adv, and a certificate is issued for a block that does not
   extend the most recently certified block — violating Peras chain-
   extension safety.
```

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L67-76)
```haskell
initialPerasCertDbState :: WithFingerprint (PerasCertDbState blk)
initialPerasCertDbState =
  WithFingerprint
    PerasCertDbState
      { pcdsCertIds = Set.empty
      , pcdsCertsByTicket = Map.empty
      , pcdsLastTicketNo = zeroPerasCertTicketNo
      , pcdsLatestCertSeen = Nothing
      }
    (Fingerprint 0)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L139-149)
```haskell
createDB args = do
  pcdbState <-
    newTVarWithInvariantIO
      (either Just (const Nothing) . invariantForPerasCertDbState)
      initialPerasCertDbState
  let env =
        PerasCertDbEnv
          { pcdbTracer
          , pcdbState
          }
  pure
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl.hs (L199-200)
```haskell
    perasCertDB <- PerasCertDB.createDB argsPerasCertDB
    perasVoteDB <- PerasVoteDB.createDB argsPerasVoteDB
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L68-72)
```haskell
  , getLatestCertSeen ::
      STM m (Maybe (WithArrivalTime (ValidatedPerasCert blk)))
  -- ^ This field impacts voting directly because having seen a certificate is a
  -- precondition for voting in any round except for the very first one
  -- (at origin).
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/View.hs (L192-202)
```haskell
data PerasVotingView cert = PerasVotingView
  { perasParams :: !PerasParams
  -- ^ Peras protocol parameters
  , currRoundNo :: !PerasRoundNo
  -- ^ The current Peras round number
  , latestCertSeen :: !(WithOrigin (LatestCertSeenView cert))
  -- ^ The most recent certificate seen by the voter
  , latestCertOnChain :: !(WithOrigin (LatestCertOnChainView cert))
  -- ^ The most recent certificate present in our preferred chain
  }
  deriving Show
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L147-149)
```haskell
        -- We have never seen a certificate ==> check if we are voting in round 0
        Origin ->
          currRoundNo :==: PerasRoundNo 0
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L168-185)
```haskell
perasVR1B ::
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR1B
  PerasVotingView
    { latestCertSeen
    } =
    VR1B := vr1b
   where
    -- The block being voted upon extends the most recently certified one
    vr1b =
      case latestCertSeen of
        -- We have seen a certificate ==> check that it extends our chain
        NotOrigin cert ->
          Bool (lcsCandidateBlockExtendsCert cert)
        -- We have never seen a certificate ==> vacuously true
        Origin ->
          Bool True
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L210-212)
```haskell
        -- an initial cooldown after having initially failed to reach a quorum
        Origin ->
          _R :<=: currRoundNo
```
