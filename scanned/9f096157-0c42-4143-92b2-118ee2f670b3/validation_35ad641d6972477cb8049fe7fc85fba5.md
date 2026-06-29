### Title
DAO Replacement of Factory Address via `add_factory` Permanently Freezes In-Flight EVM→NEAR Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The NEAR `omni-bridge` contract stores exactly one factory address per foreign chain in `self.factories`. The DAO can atomically replace that address by calling `add_factory`. Any EVM→NEAR transfer whose proof was emitted by the *old* factory address becomes permanently un-finalizable on NEAR, because `fin_transfer_callback` rejects proofs whose `emitter_address` does not equal the *current* factory. The user's tokens are already burned/locked on the EVM side with no on-chain refund path, so they are permanently frozen.

---

### Finding Description

**Step 1 – Factory storage is a single-slot-per-chain map.**

`add_factory` inserts into a `LookupMap<ChainKind, OmniAddress>` keyed by chain kind: [1](#0-0) 

Calling `add_factory` with a new address for the same chain silently overwrites the previous entry; there is no `remove_factory` and no history of prior addresses.

**Step 2 – `fin_transfer_callback` enforces an exact match against the current factory.**

When a relayer submits a proof to finalize an inbound transfer, the callback immediately checks: [2](#0-1) 

If `init_transfer.emitter_address` (the address that emitted the `InitTransfer` event on EVM) no longer equals `self.factories.get(&chain)`, the call panics with `BridgeError::UnknownFactory` and the transfer is never finalized.

**Step 3 – The EVM side has no refund path.**

`initTransfer` on EVM burns bridge tokens or locks native tokens at the moment of the call: [3](#0-2) 

There is no `cancelTransfer` or timeout-based refund function in the EVM contract. Recovery is only possible through a successful `fin_transfer` on NEAR, which is now blocked.

**Concrete scenario:**

1. User calls `initTransfer` on EVM factory `A`; tokens are burned; an `InitTransfer` event is emitted with `emitter_address = A`.
2. The DAO executes a governance proposal that calls `add_factory(B)` for the same chain (a legitimate upgrade to a new EVM bridge deployment).
3. `self.factories[Eth]` is now `B`; the old address `A` is gone.
4. The relayer calls `fin_transfer` on NEAR with the proof from step 1. `fin_transfer_callback` checks `factories[Eth] == A` → `B == A` → false → panic.
5. The user's tokens are permanently frozen on EVM with no recovery path.

---

### Impact Explanation

Permanent freezing of bridged funds. Any EVM→NEAR transfer that was initiated before a factory upgrade but not yet finalized on NEAR becomes irrecoverable. The user's tokens are already destroyed/locked on the EVM side, and the NEAR bridge will unconditionally reject the proof. This matches the allowed critical impact: *"permanent freezing of bridged funds across … EVM … flows."*

---

### Likelihood Explanation

Factory upgrades are a routine governance operation (e.g., deploying a new `OmniBridge.sol` with a bug fix or new feature). The window between an EVM `initTransfer` and its NEAR `fin_transfer` can span multiple blocks or even minutes (light-client / Wormhole VAA propagation delay). Any transfer in flight during that window is silently bricked. No attacker action is required; the DAO acting in good faith is sufficient to trigger the loss.

---

### Recommendation

1. **Maintain a set of valid factory addresses per chain** instead of a single slot, so that proofs from any previously-registered factory remain acceptable.
2. **Alternatively**, introduce a deprecation period: when `add_factory` is called, mark the old address as "deprecated" and continue accepting proofs from it for a configurable grace window.
3. **On the EVM side**, add a timeout-based `cancelTransfer` that allows users to reclaim tokens if the corresponding NEAR finalization has not occurred within a bounded period.

---

### Proof of Concept

```
// 1. User initiates transfer on EVM (factory = OLD_FACTORY)
//    → tokens burned, InitTransfer event emitted with emitter = OLD_FACTORY

// 2. DAO governance proposal executes:
contract.add_factory(NEW_FACTORY_ADDRESS_FOR_ETH);
//    → self.factories[ChainKind::Eth] = NEW_FACTORY (OLD_FACTORY overwritten)

// 3. Relayer submits proof to NEAR:
contract.fin_transfer(FinTransferArgs {
    chain_kind: ChainKind::Eth,
    prover_args: proof_with_emitter_OLD_FACTORY,
    ...
});

// 4. fin_transfer_callback panics:
//    self.factories.get(Eth) == Some(NEW_FACTORY)
//    init_transfer.emitter_address == OLD_FACTORY
//    NEW_FACTORY != OLD_FACTORY  →  BridgeError::UnknownFactory

// 5. User's EVM tokens are permanently frozen; no refund path exists.
``` [1](#0-0) [4](#0-3) [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L705-713)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1501-1504)
```rust
    #[access_control_any(roles(Role::DAO))]
    pub fn add_factory(&mut self, address: OmniAddress) {
        self.factories.insert(&(&address).into(), &address);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-395)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
```
