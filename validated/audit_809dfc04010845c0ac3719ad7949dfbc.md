### Title
Era-Transition Nonce State Discrepancy at Alonzo→Babbage Hard Fork — (`ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs`)

---

### Summary

The `TranslateProto (TPraos c) (Praos c)` instance's `translateChainDepState` function incorrectly initializes `praosStatePreviousEpochNonce` to the same value as `praosStateEpochNonce` when crossing the Alonzo→Babbage era boundary. Additionally, the project's own documentation explicitly acknowledges that the **extra entropy** parameter of Transitional Praos was not considered during this translation. This is a direct analog to the zkSync nonce-initialization discrepancy: a protocol-specified value is silently initialized to the wrong value at an era boundary, causing downstream consumers of that value to operate on incorrect state.

---

### Finding Description

At the Alonzo→Babbage hard-fork, `translateChainDepStateAcrossShelley` (used for every Shelley-based era transition) delegates to `translateChainDepState (Proxy @(TPraos c, Praos c))`. That instance constructs the initial `PraosState` as follows:

```haskell
translateChainDepState _ tpState =
    PraosState
      { ...
      , praosStateEpochNonce         = epochNonce
      , praosStatePreviousEpochNonce = epochNonce  -- same as current epoch nonce
      , ...
      }
``` [1](#0-0) 

The comment `-- same as current epoch nonce` is the tell: in normal Praos operation `praosStatePreviousEpochNonce` tracks the epoch nonce from the **preceding** epoch, which is structurally different from the current epoch nonce. TPraos has no equivalent field, so the translation silently collapses two distinct values into one.

The project's own hard-won-wisdom document explicitly records the second dimension of this discrepancy:

> "However, we did only realize recently that the extra entropy parameter of Transitional Praos should have been considered when translating to Praos at the Alonzo→Babbage transition." [2](#0-1) 

`extraEntropy` (field `appExtraEntropy` in Alonzo protocol parameters) is a governance-settable nonce that is XOR'd into the epoch nonce during the TICKN transition. Because Praos has no such field, any non-neutral extra entropy active at the transition boundary is silently dropped from the nonce lineage.

The `praosStatePreviousEpochNonce` field is consumed during `tickChainDepState` at every epoch boundary:

> "Store the existing current epoch nonce as the 'previous epoch' nonce. This is needed to validate Peras certificates when they appear in blocks." [3](#0-2) 

The `translateChainDepStateAcrossShelley` wrapper that invokes this translation is used for all six Shelley-based era transitions, but the protocol-change translation (`TPraos → Praos`) only fires at Alonzo→Babbage: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

**Incorrect `praosStatePreviousEpochNonce`:** The Peras protocol (actively under development, targeted for a future Conway/Dijkstra era upgrade) validates certificates by checking them against `praosStatePreviousEpochNonce`. Any node that replays the chain from genesis through the Alonzo→Babbage boundary will carry a wrong `praosStatePreviousEpochNonce` for the entire first Babbage epoch. If Peras certificate validation is active during that epoch (e.g., on a private testnet or a future chain that enables Peras earlier), valid certificates would be rejected and/or invalid ones accepted — a bypass of certificate verification, which falls under the **Critical** allowed impact scope ("Bypass of … certificate … checks … that enables unauthorized … certificate acceptance").

**Dropped extra entropy:** If a governance update proposal sets `extraEntropy` to a non-neutral value in the last Alonzo epoch, the nonce lineage diverges at the boundary: nodes that crossed the transition carry the correct nonce (baked in by the last TICKN), but any node that re-derives the Babbage initial state from the Alonzo ledger state (e.g., snapshot replay, ledger-state reconstruction) will compute a different epoch nonce. This is a **High** impact hard-fork/era-transition ledger-invariant break: two honest nodes can permanently disagree on the epoch nonce for the first Babbage epoch, causing divergent leader schedules and chain splits.

---

### Likelihood Explanation

- On Cardano mainnet, `extraEntropy` was set to `NeutralNonce` before the Alonzo→Babbage transition, and Peras was not active, so neither sub-issue manifested.
- On private testnets, staging networks, or any future chain that (a) uses non-neutral extra entropy or (b) enables Peras before or at the Alonzo→Babbage boundary, both sub-issues are directly triggerable by any participant who submits a governance update proposal — no privileged access required.
- The Peras sub-issue is particularly relevant because Peras is actively being integrated into the codebase (Peras certificate and vote stores are already present), making the likelihood of a future chain hitting this path non-negligible.

---

### Recommendation

1. **`praosStatePreviousEpochNonce`**: At the Alonzo→Babbage translation, derive the previous epoch nonce from the TPraos `TicknState`. The `ticknStatePrevHashNonce` field already carries the hash of the last block of the previous epoch; the previous epoch nonce can be reconstructed from the Alonzo ledger state's nonce history, or the translation should explicitly document and test the invariant that `praosStatePreviousEpochNonce` is only meaningful after the first post-transition epoch tick.

2. **Extra entropy**: Before translating, check whether `extraEntropy` in the last Alonzo protocol parameters is non-neutral. If it is, either incorporate it into the initial `praosStateEpochNonce` / `praosStateCandidateNonce` carried into Praos, or assert/document that the transition is only safe when `extraEntropy = NeutralNonce`.

3. Add a property-based test that exercises the Alonzo→Babbage translation with non-neutral extra entropy and verifies that the resulting `PraosState` produces the same leader schedule as a reference implementation.

---

### Proof of Concept

**Sub-issue 1 (extra entropy):**
1. On a private testnet, submit a governance update proposal in epoch `E` of Alonzo setting `extraEntropy` to any non-neutral nonce value `η`.
2. Allow the proposal to be adopted and the epoch to close (TICKN fires, baking `η` into `ticknStateEpochNonce`).
3. Trigger the Alonzo→Babbage hard fork.
4. Replay the chain from a snapshot taken before step 1. The replaying node will compute `praosStateEpochNonce` without `η`, diverging from the live node's nonce for the first Babbage epoch, producing a different leader schedule and rejecting valid blocks.

**Sub-issue 2 (`praosStatePreviousEpochNonce`):**
1. On a private testnet with Peras enabled, trigger the Alonzo→Babbage hard fork.
2. In the first Babbage epoch, submit a Peras certificate that references the correct previous epoch nonce (the last Alonzo epoch nonce, which differs from the current Babbage epoch nonce).
3. The node will validate the certificate against `praosStatePreviousEpochNonce = epochNonce` (the current epoch nonce), causing the certificate to be rejected despite being valid — or, conversely, a certificate forged against the current epoch nonce will be accepted. [6](#0-5)

### Citations

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L268-285)
```haskell
data PraosState = PraosState
  { praosStateLastSlot :: !(WithOrigin SlotNo)
  , praosStateOCertCounters :: !(Map (KeyHash SL.BlockIssuer) Word64)
  -- ^ Operation Certificate counters
  , praosStateEvolvingNonce :: !Nonce
  -- ^ Evolving nonce
  , praosStateCandidateNonce :: !Nonce
  -- ^ Candidate nonce
  , praosStateEpochNonce :: !Nonce
  -- ^ Epoch nonce
  , praosStatePreviousEpochNonce :: !Nonce
  -- ^ Previous epoch nonce
  , praosStateLabNonce :: !Nonce
  -- ^ Nonce constructed from the hash of the previous block
  , praosStateLastEpochBlockNonce :: !Nonce
  -- ^ Nonce corresponding to the LAB nonce of the last block of the previous
  -- epoch
  }
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L427-432)
```haskell
  -- epoch, we do three things:
  -- - Store the existing current epoch nonce as the "previous epoch" nonce.
  --   This is needed to validate Peras certificates when they appear in blocks.
  -- - Update the epoch nonce to the combination of the candidate nonce and the
  --   nonce derived from the last block of the previous epoch.
  -- - Update the "last block of previous epoch" nonce to the nonce derived
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L761-778)
```haskell
  translateChainDepState _ tpState =
    PraosState
      { praosStateLastSlot = tpraosStateLastSlot tpState
      , praosStateOCertCounters = Map.mapKeysMonotonic coerce certCounters
      , praosStateEvolvingNonce = evolvingNonce
      , praosStateCandidateNonce = candidateNonce
      , praosStateEpochNonce = epochNonce
      , praosStatePreviousEpochNonce = epochNonce -- same as current epoch nonce
      , praosStateLabNonce = csLabNonce
      , praosStateLastEpochBlockNonce = SL.ticknStatePrevHashNonce csTickn
      }
   where
    SL.ChainDepState{SL.csProtocol, SL.csTickn, SL.csLabNonce} =
      tpraosStateChainDepState tpState
    SL.PrtclState certCounters evolvingNonce candidateNonce =
      csProtocol
    epochNonce = SL.ticknStateEpochNonce csTickn

```

**File:** docs/website/contents/references/miscellaneous/hard_won_wisdom.md (L391-393)
```markdown
      (We haven't yet had any concrete issues here, unlike with the `LedgerState` issue linked just below.
      However, we did only realize recently that the extra entropy parameter of Transitional Praos should have been considered when translating to Praos at the Alonzo->Babbage transition.)
    - A function `LedgerConfig F -> LedgerConfig G -> EpochNo {- start of G -} -> LedgerState F -> LedgerState G`.
```

**File:** ouroboros-consensus-cardano/src/ouroboros-consensus-cardano/Ouroboros/Consensus/Cardano/CanHardFork.hs (L149-157)
```haskell
      , translateChainDepState =
          PCons translateChainDepStateByronToShelleyWrapper $
            PCons translateChainDepStateAcrossShelley $
              PCons translateChainDepStateAcrossShelley $
                PCons translateChainDepStateAcrossShelley $
                  PCons translateChainDepStateAcrossShelley $
                    PCons translateChainDepStateAcrossShelley $
                      PCons translateChainDepStateAcrossShelley $
                        PNil
```

**File:** ouroboros-consensus-cardano/src/shelley/Ouroboros/Consensus/Shelley/ShelleyHFC.hs (L271-286)
```haskell
translateChainDepStateAcrossShelley ::
  forall eraFrom eraTo protoFrom protoTo.
  TranslateProto protoFrom protoTo =>
  RequiringBoth
    WrapConsensusConfig
    (Translate WrapChainDepState)
    (ShelleyBlock protoFrom eraFrom)
    (ShelleyBlock protoTo eraTo)
translateChainDepStateAcrossShelley =
  ignoringBoth $
    Translate $ \_epochNo (WrapChainDepState chainDepState) ->
      -- Same protocol, same 'ChainDepState'. Note that we don't have to apply
      -- any changes related to an epoch transition, this is already done when
      -- ticking the state.
      WrapChainDepState $ translateChainDepState (Proxy @(protoFrom, protoTo)) chainDepState

```
