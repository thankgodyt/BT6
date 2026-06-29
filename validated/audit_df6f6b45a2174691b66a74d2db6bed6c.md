### Title
Undeployed Native Token Causes Permanent Revert of `fin_transfer_callback` for Transfers with `native_fee > 0` — (`File: near/omni-bridge/src/lib.rs`)

### Summary

The NEAR Omni Bridge represents native tokens (ETH, SOL, etc.) as zero addresses via `OmniAddress::new_zero(chain_kind)`. When a transfer arrives from a foreign chain with `native_fee > 0`, the bridge calls `get_native_token_id(origin_chain)`, which looks up the zero address in `token_address_to_id`. If the native token for that chain has not been deployed via `deploy_native_token`, the lookup panics with `TokenNotRegistered`, causing `fin_transfer_callback` to revert entirely. Because the source chain has already locked or burned the user's tokens, and the NEAR finalization permanently fails, the user's funds are stuck.

### Finding Description

**Root cause — `get_native_token_id` panics on unregistered zero address:**

`get_native_token_id` constructs the zero address for the given chain and delegates to `get_token_id`:

```rust
// near/omni-bridge/src/lib.rs:1407-1412
pub fn get_native_token_id(&self, chain: ChainKind) -> AccountId {
    let native_token_address =
        get_native_token_address(chain).near_expect(BridgeError::FailedToGetNativeTokenAddress);
    self.get_token_id(&native_token_address)
}
```

`get_native_token_address` returns the zero address for every chain except Starknet:

```rust
// near/omni-types/src/lib.rs:944-961
pub fn get_native_token_address(chain_kind: ChainKind) -> Result<OmniAddress, String> {
    match chain_kind {
        ChainKind::Strk => OmniAddress::from_str("strk:0x04718f5a0..."),
        ChainKind::Eth | ChainKind::Sol | ChainKind::Arb | ... => OmniAddress::new_zero(chain_kind),
    }
}
```

`get_token_id` then looks up the zero address in `token_address_to_id` and panics if absent:

```rust
// near/omni-bridge/src/lib.rs:1368-1376
pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
    if let OmniAddress::Near(token_account_id) = address {
        token_account_id.clone()
    } else {
        self.token_address_to_id
            .get(address)
            .near_expect(BridgeError::TokenNotRegistered)  // panics here
    }
}
```

**Vulnerable call site — inside `process_fin_transfer_to_near`:**

When `native_fee > 0`, `process_fin_transfer_to_near` calls `get_native_token_id` to validate the storage deposit action for the fee recipient:

```rust
// near/omni-bridge/src/lib.rs:1935-1948
if transfer_message.fee.native_fee.0 > 0 {
    let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());
    require!(
        Self::check_storage_balance_result(...) &&
        storage_deposit_actions[...].token_id == native_token_id,
        BridgeError::StorageNativeFeeRecipientOmitted.as_ref()
    );
}
```

This executes within the `fin_transfer_callback` execution context. A panic here reverts all state changes in that context — including `add_fin_transfer` — so the transfer is never marked finalized and can never be retried successfully.

**Second vulnerable call site — `fin_transfer_send_tokens_callback`:**

```rust
// near/omni-bridge/src/lib.rs:1736-1742
if transfer_message.fee.native_fee.0 > 0 {
    let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());
    ext_token::ext(native_token_id)
        .with_static_gas(MINT_TOKEN_GAS)
        .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
        .detach();
}
```

And in `send_fee_internal` (called from `claim_fee_callback`):

```rust
// near/omni-bridge/src/lib.rs:2669-2672
ext_token::ext(self.get_native_token_id(origin_chain))
    .with_static_gas(MINT_TOKEN_GAS)
    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
    .detach();
```

### Impact Explanation

A user initiates a transfer from a foreign chain (e.g., Ethereum) to NEAR with `native_fee > 0`. The source chain contract locks or burns the user's tokens. When the relayer submits the proof to NEAR, `fin_transfer_callback` → `process_fin_transfer_to_near` panics at the `get_native_token_id` call because the native token for that chain has not been deployed via `deploy_native_token`. The entire callback reverts. The transfer ID is never added to `finalised_transfers`, so the proof can be resubmitted — but every resubmission will fail identically. The user's tokens remain locked or burned on the source chain with no path to recovery until the DAO deploys the native token. If the DAO never does so, the funds are permanently frozen.

### Likelihood Explanation

The `native_fee` field is user-controlled at the source chain level. The EVM `OmniBridge.sol` `initTransfer` function accepts any `native_fee` value without validating that the corresponding native token has been deployed on NEAR. Any user who sets `native_fee > 0` for a transfer from a chain whose native token is not yet registered on NEAR will trigger this failure. This is especially likely during the onboarding of new chains (e.g., `HyperEvm`, `Abs`, `Fogo`) where the chain may be added to the bridge before `deploy_native_token` is called.

### Recommendation

1. In `fin_transfer_callback` (or `process_fin_transfer_to_near`), before processing a transfer with `native_fee > 0`, check whether the native token for the origin chain is registered. If not, either reject the transfer with a clear error or treat `native_fee` as zero and refund it to the sender.
2. Alternatively, enforce on the source chain side that `native_fee > 0` is only accepted when the native token is known to be deployed on NEAR.
3. Add a guard in `get_native_token_id` that returns `Option<AccountId>` instead of panicking, allowing callers to handle the missing-token case gracefully.

### Proof of Concept

1. DAO adds a new chain (e.g., `HyperEvm`) to the bridge but does not call `deploy_native_token(HyperEvm, ...)`.
2. User calls `initTransfer` on the HyperEvm `OmniBridge` contract with `native_fee = 1000` and `amount = 100_000`. Tokens are locked in the EVM bridge.
3. Relayer submits the proof to NEAR via `fin_transfer(...)`.
4. `fin_transfer_callback` decodes the proof, calls `process_fin_transfer_to_near`.
5. At line 1935, `get_native_token_id(ChainKind::HyperEvm)` is called → `get_native_token_address(HyperEvm)` returns `OmniAddress::HyperEvm(H160::ZERO)` → `token_address_to_id.get(HyperEvm(H160::ZERO))` returns `None` → `near_expect(TokenNotRegistered)` panics.
6. `fin_transfer_callback` reverts. Transfer is never finalized.
7. User's tokens remain locked in the EVM bridge with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1368-1376)
```rust
    pub fn get_token_id(&self, address: &OmniAddress) -> AccountId {
        if let OmniAddress::Near(token_account_id) = address {
            token_account_id.clone()
        } else {
            self.token_address_to_id
                .get(address)
                .near_expect(BridgeError::TokenNotRegistered)
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1407-1412)
```rust
    pub fn get_native_token_id(&self, chain: ChainKind) -> AccountId {
        let native_token_address =
            get_native_token_address(chain).near_expect(BridgeError::FailedToGetNativeTokenAddress);

        self.get_token_id(&native_token_address)
    }
```

**File:** near/omni-bridge/src/lib.rs (L1736-1742)
```rust
            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
```

**File:** near/omni-bridge/src/lib.rs (L1935-1948)
```rust
        if transfer_message.fee.native_fee.0 > 0 {
            let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

            require!(
                Self::check_storage_balance_result(
                    (storage_deposit_action_index + 1)
                        .try_into()
                        .near_expect(BridgeError::Cast)
                ) && storage_deposit_actions[storage_deposit_action_index].account_id
                    == fee_recipient
                    && storage_deposit_actions[storage_deposit_action_index].token_id
                        == native_token_id,
                BridgeError::StorageNativeFeeRecipientOmitted.as_ref()
            );
```

**File:** near/omni-bridge/src/lib.rs (L2669-2672)
```rust
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
```

**File:** near/omni-types/src/lib.rs (L197-213)
```rust
    pub fn new_zero(chain_kind: ChainKind) -> Result<Self, String> {
        match chain_kind {
            ChainKind::Eth => Ok(Self::Eth(H160::ZERO)),
            ChainKind::Near => Ok(Self::Near(ZERO_ACCOUNT_ID.parse().map_err(stringify)?)),
            ChainKind::Sol => Ok(Self::Sol(SolAddress::ZERO)),
            ChainKind::Arb => Ok(Self::Arb(H160::ZERO)),
            ChainKind::Base => Ok(Self::Base(H160::ZERO)),
            ChainKind::Bnb => Ok(Self::Bnb(H160::ZERO)),
            ChainKind::Pol => Ok(Self::Pol(H160::ZERO)),
            ChainKind::HyperEvm => Ok(Self::HyperEvm(H160::ZERO)),
            ChainKind::Btc => Ok(Self::Btc(String::new())),
            ChainKind::Zcash => Ok(Self::Zcash(String::new())),
            ChainKind::Strk => Ok(Self::Strk(H256::ZERO)),
            ChainKind::Abs => Ok(Self::Abs(H160::ZERO)),
            ChainKind::Fogo => Ok(Self::Fogo(SolAddress::ZERO)),
        }
    }
```

**File:** near/omni-types/src/lib.rs (L944-961)
```rust
pub fn get_native_token_address(chain_kind: ChainKind) -> Result<OmniAddress, String> {
    match chain_kind {
        ChainKind::Strk => OmniAddress::from_str(
            "strk:0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
        ),
        ChainKind::Eth
        | ChainKind::Near
        | ChainKind::Sol
        | ChainKind::Arb
        | ChainKind::Base
        | ChainKind::Bnb
        | ChainKind::Btc
        | ChainKind::Zcash
        | ChainKind::Pol
        | ChainKind::HyperEvm
        | ChainKind::Abs
        | ChainKind::Fogo => OmniAddress::new_zero(chain_kind),
    }
```
