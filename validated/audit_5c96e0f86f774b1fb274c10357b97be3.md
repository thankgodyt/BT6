### Title
Factory Address Overwrite During Migration Permanently Freezes In-Flight EVM→NEAR Transfers - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `add_factory` function silently overwrites the single registered factory address per chain. When the DAO migrates to a new EVM bridge contract, any EVM→NEAR transfer that was initiated from the old factory but not yet finalized on NEAR will permanently fail the `ERR_UNKNOWN_FACTORY` check in `fin_transfer_callback`. For deployed (bridged) tokens, the user's tokens are already burned on EVM and cannot be minted on NEAR, resulting in permanent loss.

### Finding Description

`add_factory` stores exactly one factory address per `ChainKind` in a `LookupMap<ChainKind, OmniAddress>`:

```rust
pub fn add_factory(&mut self, address: OmniAddress) {
    self.factories.insert(&(&address).into(), &address);
}
``` [1](#0-0) 

`LookupMap::insert` silently overwrites the existing value. There is no `remove_factory`, no multi-factory-per-chain support, and no grace period.

Both `fin_transfer_callback` and `claim_fee_callback` enforce a strict equality check against the currently registered factory:

```rust
require!(
    self.factories
        .get(&init_transfer.emitter_address.get_chain())
        == Some(init_transfer.emitter_address),
    BridgeError::UnknownFactory.as_ref()
);
``` [2](#0-1) [3](#0-2) 

The `emitter_address` in the proof is the EVM bridge contract address that emitted the `InitTransfer` event. If the DAO calls `add_factory` with a new EVM bridge address (e.g., during an upgrade), the old address is gone. Any proof from the old factory will fail the check permanently.

There is no public cancel or refund function for in-flight transfers. `remove_transfer_message` is only called internally on successful finalization or fee claim. [4](#0-3) 

The `Contract` struct confirms only one factory per chain: [5](#0-4) 

### Impact Explanation

For **deployed (bridged) tokens** (e.g., a NEAR-deployed ERC-20 representation): the EVM `initTransfer` burns the user's tokens on EVM. If `fin_transfer` subsequently fails the factory check on NEAR, the tokens are permanently destroyed — burned on EVM, unmintable on NEAR. This is an irreversible loss of bridged funds.

For **native tokens** (locked on EVM): tokens are locked in the old EVM bridge contract. Recovery depends on whether the old EVM contract has a cancel path, which is a separate concern.

The `pending_transfers` map retains the NEAR-side transfer record indefinitely with no expiry and no user-callable cancel, so the user's NEAR storage deposit is also permanently locked. [6](#0-5) 

### Likelihood Explanation

Factory migration is an expected operational event. The repository includes a dedicated `upgrade-factory` Hardhat task and the `add_factory` admin function is the only mechanism to update the EVM bridge address. Any upgrade of the EVM `OmniBridge` contract requires calling `add_factory` with the new proxy address, which atomically removes the old one. During the window between the EVM upgrade and NEAR factory update (or vice versa), all in-flight transfers are trapped. This is most likely to occur as an error during a factory migration — exactly the scenario described in the reference report. [1](#0-0) 

### Recommendation

1. **Support multiple factories per chain** by changing `factories` to `LookupMap<OmniAddress, bool>` (a set), so old and new factory addresses can coexist during migration.
2. **Add a `remove_factory` function** that allows the DAO to explicitly deregister an old factory only after confirming no in-flight transfers remain.
3. **Add a user-callable `cancel_transfer`** that allows the original sender to reclaim their locked/burned tokens if a transfer has been pending beyond a timeout, providing a recovery path analogous to `forceUndelegate` in the reference report.

### Proof of Concept

1. User calls `initTransfer` on the old EVM `OmniBridge` at address `0xOLD`. Tokens are burned. The emitted `InitTransfer` event has `emitter_address = Eth(0xOLD)`.
2. DAO calls `add_factory(Eth(0xNEW))` on the NEAR bridge to upgrade to a new EVM contract. `self.factories[ChainKind::Eth]` is now `Eth(0xNEW)`.
3. Relayer submits the proof from step 1 via `fin_transfer`. The prover verifies the EVM receipt and returns `InitTransferMessage { emitter_address: Eth(0xOLD), ... }`.
4. `fin_transfer_callback` executes: `self.factories.get(&ChainKind::Eth) == Some(Eth(0xOLD))` → `Some(Eth(0xNEW)) != Some(Eth(0xOLD))` → panics with `ERR_UNKNOWN_FACTORY`.
5. The user's tokens are burned on EVM and permanently unrecoverable on NEAR. The transfer remains in `pending_transfers` with no cancel path. [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L220-222)
```rust
pub struct Contract {
    pub factories: LookupMap<ChainKind, OmniAddress>,
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
```

**File:** near/omni-bridge/src/lib.rs (L700-713)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
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

**File:** near/omni-bridge/src/lib.rs (L1087-1092)
```rust
        require!(
            self.factories
                .get(&fin_transfer.emitter_address.get_chain())
                == Some(fin_transfer.emitter_address),
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

**File:** near/omni-bridge/src/lib.rs (L2194-2211)
```rust
    fn remove_transfer_message(&mut self, transfer_id: TransferId) -> TransferMessage {
        let storage_usage = env::storage_usage();
        let transfer = self
            .pending_transfers
            .remove(&transfer_id)
            .map(storage::TransferMessageStorage::into_main)
            .near_expect(BridgeError::TransferNotExist);

        let refund =
            env::storage_byte_cost().saturating_mul((storage_usage - env::storage_usage()).into());

        if let Some(mut storage) = self.accounts_balances.get(&transfer.owner) {
            storage.available = storage.available.saturating_add(refund);
            self.accounts_balances.insert(&transfer.owner, &storage);
        }

        transfer.message
    }
```
