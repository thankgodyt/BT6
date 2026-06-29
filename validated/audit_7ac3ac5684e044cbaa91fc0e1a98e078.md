Audit Report

## Title
Missing Pre-Normalization Check in `init_transfer` Causes Permanent Token Loss — (`near/omni-bridge/src/lib.rs`)

## Summary
`init_transfer` burns or locks user tokens before verifying that the post-fee normalized transfer amount is non-zero. The normalization guard only exists in `sign_transfer`, which panics with `InvalidAmountToTransfer` after the tokens are already destroyed or frozen. No cancel or recovery path exists in the contract, leaving the funds permanently lost.

## Finding Description

**Step 1 — `init_transfer` / `init_transfer_internal`:**

The only fee validation in `init_transfer` is:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [1](#0-0) 

After this passes, `init_transfer_internal` immediately burns deployed tokens and locks native tokens:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(
    transfer_message.get_destination_chain(),
    &token_id,
    transfer_message.amount.0,
);
``` [2](#0-1) 

`burn_tokens_if_needed` calls `burn` with `.detach()`, making it fire-and-forget with no rollback: [3](#0-2) 

**Step 2 — `sign_transfer`:**

The relayer calls `sign_transfer`, which computes the normalized amount and enforces:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [4](#0-3) 

`normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [5](#0-4) 

The code's own comment acknowledges that when `fee = 0`, dust "stays locked/burned" — but this comment addresses sub-unit remainders, not the case where the entire `amount - fee` normalizes to zero. [6](#0-5) 

**No recovery path:** A search of the contract reveals no `cancel_transfer`, `rescue`, or user-callable refund function for pending outbound transfers. `remove_transfer_message` is internal-only. Once `init_transfer_internal` returns `U128(0)`, the tokens are gone and the transfer sits in `pending_transfers` indefinitely. [7](#0-6) 

## Impact Explanation

This is a **permanent freezing / loss of bridged funds**, matching the Critical allowed impact: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet."*

- **Deployed (bridge) tokens**: `burn` is called with `.detach()` — the tokens are destroyed on-chain with no recovery regardless of any administrative action.
- **Native (locked) tokens**: Funds are locked inside the bridge contract. The DAO's `set_locked_tokens` adjusts accounting only; there is no function to release locked tokens back to the original sender.

## Likelihood Explanation

Any unprivileged user who calls `ft_transfer_call` on a token contract pointing to the bridge can trigger this. The user controls `amount` and `fee`. For any token pair where `origin_decimals > dest_decimals` (e.g., 24 vs 6, a difference of 18), any `amount - fee < 10^18` causes `normalize_amount` to return 0. For NEAR-native tokens with 24 decimals bridging to a 6-decimal EVM token, the threshold is 1 NEAR — easily reachable accidentally or deliberately. No special role or privilege is required.

## Recommendation

Add a normalization check inside `init_transfer` (before `init_transfer_internal` is called) to reject transfers where the post-fee normalized amount would be zero. This mirrors the guard already present in `sign_transfer`:

```rust
// After building transfer_message, before calling init_transfer_internal:
if let Some(token_address) = self.get_token_address(
    init_transfer_msg.get_destination_chain(), token_id.clone()
) {
    if let Some(decimals) = self.token_decimals.get(&token_address) {
        let normalized = Self::normalize_amount(
            transfer_message.amount_without_fee().unwrap_or(0),
            decimals,
        );
        require!(normalized > 0, BridgeError::InvalidAmountToTransfer.as_ref());
    }
}
```

This check should be placed after the `fee < amount` guard at line 554 and before the call to `init_transfer_internal` at line 583. [8](#0-7) 

## Proof of Concept

1. Register a token pair with `origin_decimals = 24`, `dest_decimals = 6` (normalization divisor = `10^18`).
2. Call `ft_transfer_call` on the token contract with `receiver_id = omni-bridge`, `amount = "999999999999999999"` (i.e., `< 10^18`), `msg = InitTransferMsg { fee: 0, ... }`.
3. Observe: `ft_on_transfer` → `init_transfer` passes the `fee < amount` check (0 < 999...999 ✓). `init_transfer_internal` is called. For a deployed token, `burn_tokens_if_needed` fires and destroys the tokens. The function returns `U128(0)` (no refund). `InitTransferEvent` is emitted.
4. Call `sign_transfer` with the resulting `transfer_id`.
5. Observe: `normalize_amount(999999999999999999, {24, 6}) = 999999999999999999 / 10^18 = 0`. The `require!(amount_to_transfer > 0, ...)` panics with `ERR_INVALID_AMOUNT_TO_TRANSFER`. The transfer remains in `pending_transfers`. The burned tokens are permanently lost.

A local unit test can be written against `init_transfer_internal` + `sign_transfer` using the existing test harness in `near/omni-bridge/src/tests/lib_test.rs`, registering a token with the described decimal configuration and asserting that `sign_transfer` panics while the token balance is not restored. [9](#0-8)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-485)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L554-584)
```rust
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );

        let required_storage_balance =
            self.required_balance_for_init_transfer_message(transfer_message.clone());

        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));

        // Choose storage payer or whether to yield execution until storage is available
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
            )
```

**File:** near/omni-bridge/src/lib.rs (L1806-1812)
```rust
    fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
        if self.is_deployed_token(&token) {
            ext_token::ext(token)
                .with_static_gas(BURN_TOKEN_GAS)
                .burn(amount)
                .detach();
        }
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
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

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** near/omni-bridge/src/tests/lib_test.rs (L268-312)
```rust
#[test]
fn test_init_transfer_locks_other_tokens_for_deployed_token() {
    let mut contract = get_default_contract();
    let token_id: AccountId = "eth-token.testnet".parse().expect("Invalid token ID");
    let locked_amount = DEFAULT_TRANSFER_AMOUNT;

    contract.deployed_tokens.insert(&token_id);
    contract
        .deployed_tokens_v2
        .insert(&token_id, &ChainKind::Eth);
    contract
        .locked_tokens
        .insert(&(ChainKind::Sol, token_id.clone()), &0);
    contract
        .locked_tokens
        .insert(&(ChainKind::Near, token_id.clone()), &locked_amount);

    let solana_address: SolAddress = "2xNweLHLqbS9YpP3UyaPrxKqgqoC6yPBFyuLxA8qtgr4"
        .parse()
        .expect("Invalid Solana address");

    run_ft_on_transfer(
        &mut contract,
        DEFAULT_NEAR_USER_ACCOUNT.to_string(),
        token_id.to_string(),
        U128(locked_amount),
        None,
        &BridgeOnTransferMsg::InitTransfer(InitTransferMsg {
            recipient: OmniAddress::Sol(solana_address),
            fee: U128(0),
            native_token_fee: U128(0),
            msg: None,
            external_id: None,
        }),
    );

    assert_eq!(
        contract.get_locked_tokens(ChainKind::Near, token_id.clone()),
        Some(U128(locked_amount))
    );
    assert_eq!(
        contract.get_locked_tokens(ChainKind::Sol, token_id),
        Some(U128(locked_amount))
    );
}
```
