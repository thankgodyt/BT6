### Title
`signer_account_id` (`tx.origin` Analog) Used as Storage Payer in `ft_on_transfer` Enables Storage Balance Theft via Malicious Token - (File: `near/omni-bridge/src/lib.rs`)

### Summary

`ft_on_transfer` in the NEAR omni-bridge contract uses `env::signer_account_id()` — NEAR's direct analog of Ethereum's `tx.origin` — as the storage-payment identity. A malicious NEP-141 token contract can call `ft_on_transfer` on the bridge while a victim is the transaction signer, causing the bridge to deduct the victim's pre-deposited storage balance to fund a bogus transfer record the victim never authorized.

### Finding Description

In `near/omni-bridge/src/lib.rs`, `ft_on_transfer` is the NEP-141 receiver callback. The code explicitly acknowledges that `sender_id` (the parameter passed by the calling token contract) cannot be trusted, and substitutes `env::signer_account_id()` as the storage payer: [1](#0-0) 

```rust
// We can't trust sender_id to pay for storage as it can be spoofed.
let signer_id = env::signer_account_id();
let promise_or_promise_index_or_value = match parsed_msg {
    BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
        self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
```

`env::signer_account_id()` is the original transaction signer — equivalent to `tx.origin` in Solidity. It is not the immediate caller (`env::predecessor_account_id()`). Any contract in the call chain can exploit this.

Inside `init_transfer`, `signer_id` is used as the storage payer: [2](#0-1) 

If the victim (`signer_id`) has sufficient storage balance, the bridge deducts it and records the transfer: [3](#0-2) 

The storage balance is real NEAR tokens deposited by the victim via `storage_deposit`: [4](#0-3) 

### Impact Explanation

The victim's NEAR storage balance — real NEAR tokens locked in the bridge — is consumed to pay for a transfer record the victim never initiated. The attacker controls `sender_id`, `amount`, and `msg` (the `InitTransferMsg`), so the bogus transfer is recorded with attacker-chosen parameters. The victim's `available` storage balance is reduced by the cost of the transfer message storage. If the victim's entire balance is consumed across repeated calls, they lose all deposited NEAR and can no longer initiate legitimate bridge transfers.

This is a direct balance manipulation: real NEAR tokens are mis-accounted from the victim's storage balance to fund attacker-crafted state.

### Likelihood Explanation

The attack requires only that the victim:
1. Has a storage balance registered in the omni-bridge (required for any bridge user who has ever initiated a transfer).
2. Interacts with any malicious NEP-141 token — e.g., by calling `ft_transfer_call` on it, or by any contract that calls `ft_transfer_call` on the malicious token on the victim's behalf.

The malicious token's `ft_transfer_call` implementation calls `ft_on_transfer` on the bridge with a crafted `msg`. Since `ft_on_transfer` is a public method, the malicious token can also call it directly without going through `ft_transfer_call` at all, as long as the victim is the current `signer_account_id()`. The attack is permissionless and requires no admin access.

### Recommendation

Replace `env::signer_account_id()` with a properly authenticated identity. Options:

1. **Require the storage payer to be `sender_id` and verify `sender_id` matches `predecessor_account_id()`** — i.e., only allow direct (non-intermediated) `ft_transfer_call` flows where the token contract is the immediate predecessor and `sender_id` is the actual user.
2. **Require an explicit storage deposit attached to the `ft_transfer_call`** via `env::attached_deposit()` rather than drawing from a pre-registered balance attributed to `signer_account_id()`.
3. **Remove reliance on `signer_account_id()` entirely** for any authorization or balance-deduction purpose, consistent with NEAR security best practices.

### Proof of Concept

1. Victim `alice.near` has 1 NEAR of storage balance in the omni-bridge.
2. Attacker deploys `evil.near`, a NEP-141 token whose `ft_transfer_call` implementation calls `omni-bridge.near::ft_on_transfer` with `sender_id = "attacker.near"`, `amount = 1`, `msg = <valid InitTransferMsg targeting attacker's EVM address>`.
3. Attacker airdrops `evil.near` tokens to `alice.near`.
4. `alice.near` calls `evil.near::ft_transfer_call(...)` to sell the airdropped tokens.
5. `evil.near` calls `omni-bridge.near::ft_on_transfer("attacker.near", 1, <crafted msg>)`.
6. Inside `ft_on_transfer`: `token_id = evil.near`, `sender_id = "attacker.near"`, `signer_id = alice.near` (from `env::signer_account_id()`).
7. Bridge checks `alice.near`'s storage balance — sufficient — and deducts it to record the bogus transfer.
8. `alice.near`'s NEAR storage balance is drained. The bridge emits `InitTransferEvent` for a transfer `alice.near` never authorized.
9. Repeat until `alice.near`'s balance is exhausted. [5](#0-4)

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-283)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
    }
```

**File:** near/omni-bridge/src/lib.rs (L566-583)
```rust
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
```

**File:** near/omni-bridge/src/storage.rs (L140-168)
```rust
    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>) -> StorageBalance {
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        let amount = env::attached_deposit();
        let storage = self.accounts_balances.get(&account_id).map_or_else(
            || {
                let min_required_storage_balance = self.required_balance_for_account();
                let available = amount
                    .checked_sub(min_required_storage_balance)
                    .near_expect(StorageError::NotEnoughStorageBalanceAttached {
                        required: min_required_storage_balance,
                        attached: amount,
                    });
                StorageBalance {
                    total: amount,
                    available,
                }
            },
            |mut storage| {
                storage.total = storage.total.saturating_add(amount);
                storage.available = storage.available.saturating_add(amount);
                storage
            },
        );
        self.accounts_balances.insert(&account_id, &storage);

        self.resume_promise(&account_id).detach();

        storage
```
