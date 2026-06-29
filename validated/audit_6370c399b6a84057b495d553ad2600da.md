### Title
User's `native_fee` Is Permanently Locked When Trusted Relayers Are Inactive — (`near/omni-bridge/src/lib.rs`)

### Summary

When a user initiates a NEAR→Foreign transfer with a non-zero `native_fee`, that fee is immediately deducted from their storage balance inside `init_transfer_internal`. If no trusted relayer ever completes the transfer by calling `sign_transfer` followed by `claim_fee`, the user's `native_fee` (NEAR tokens) is permanently locked in the bridge's storage accounting with no user-accessible recovery path. The user is penalized for the relayer's inactivity despite having done nothing wrong.

### Finding Description

The outbound transfer flow is:

1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer` → `init_transfer_internal`.
2. Inside `init_transfer_internal`, the user's tokens are burned/locked **and** the `native_fee` is deducted from the user's `available` storage balance as part of `required_storage_balance`:

```rust
let required_storage_balance = self
    .add_transfer_message(transfer_message.clone(), storage_owner.clone())
    .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));
``` [1](#0-0) 

3. The `native_fee` is only released when a trusted relayer calls `claim_fee` → `claim_fee_callback` → `remove_transfer_message` (which credits the storage refund back) → `send_fee_internal` (which sends the `native_fee` NEAR to the relayer). [2](#0-1) 

4. The `update_transfer_fee` function enforces a **one-directional** fee constraint: the `native_fee` can only be increased, never decreased:

```rust
let diff_native_fee = fee
    .native_fee
    .0
    .checked_sub(current_fee.native_fee.0)
    .near_expect(BridgeError::LowerFee);
``` [3](#0-2) 

5. There is **no cancel-transfer function** anywhere in the contract. The user has no way to unilaterally abort a pending transfer and recover their locked tokens or `native_fee`.

If trusted relayers are inactive (all go offline, lose keys, or simply ignore the transfer), the user's `native_fee` NEAR tokens remain locked in the bridge's storage accounting indefinitely. The user cannot withdraw them via `storage_withdraw` because they are not in the `available` balance — they are consumed by `required_storage_balance`. [4](#0-3) 

### Impact Explanation

The user suffers two simultaneous losses when relayers are inactive:

- **Bridged tokens**: burned (for deployed tokens) or locked (for non-deployed tokens) with no recovery path.
- **`native_fee` NEAR**: deducted from the user's storage balance and permanently inaccessible via `storage_withdraw`.

Even if the DAO eventually adds a new trusted relayer who completes the transfer, the `native_fee` flows to that relayer — not back to the user. The user is penalized for the original relayer's inactivity regardless of outcome. This constitutes permanent freezing of bridged funds and permanent loss of the `native_fee`, matching the "Critical — permanent freezing of bridged funds" impact category.

### Likelihood Explanation

**Low.** Trusted relayers are permissioned accounts (`#[trusted_relayer]` macro enforced on `sign_transfer`). Inactivity requires all registered trusted relayers to go offline or become unresponsive simultaneously. This is a realistic but uncommon operational failure (infrastructure outage, key loss, business discontinuation). The user has no way to detect this condition in advance and no recourse once it occurs. [5](#0-4) 

### Recommendation

Add a user-callable `cancel_transfer` function that:
1. Verifies the caller is the original sender of the pending transfer.
2. Calls `remove_transfer_message` to release the storage refund.
3. Returns the `native_fee` NEAR to the sender (reversing the `required_storage_balance` deduction).
4. Unlocks or re-mints the bridged tokens back to the sender.

Alternatively, enforce a time-lock: if a transfer has been pending for longer than a configurable deadline without a `sign_transfer` call, allow the sender to self-cancel and recover all locked funds including the `native_fee`.

### Proof of Concept

1. User calls `ft_transfer_call` on a NEAR token with `native_token_fee = 1 NEAR` and `fee = 0`, targeting an ETH recipient.
2. `init_transfer_internal` burns the user's tokens and deducts `1 NEAR` from the user's `available` storage balance.
3. All trusted relayers go offline. No one calls `sign_transfer`.
4. User calls `update_transfer_fee` attempting to set `native_fee = 0` → **panics** with `ERR_LOWER_FEE`.
5. User calls `storage_withdraw` → only the remaining `available` balance (excluding the locked `native_fee`) is returned.
6. The `1 NEAR` `native_fee` and the bridged tokens are permanently inaccessible to the user. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L411-415)
```rust
                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);
```

**File:** near/omni-bridge/src/lib.rs (L444-447)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
```

**File:** near/omni-bridge/src/lib.rs (L508-520)
```rust
        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
```

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1094-1133)
```rust
        let transfer_message = self.remove_transfer_message(fin_transfer.transfer_id);

        if let Some(origin_transfer_id) = transfer_message.origin_transfer_id.clone() {
            let mut fast_transfer = FastTransfer::from_transfer(
                transfer_message.clone(),
                self.get_token_id(&transfer_message.token),
            );
            fast_transfer.transfer_id = origin_transfer_id;

            if let Some(fast_transfer_status) = self.get_fast_transfer_status(&fast_transfer.id()) {
                // For fast transfers we need to wait for finalization of the first leg (Origin chain -> Near) before allowing fee claim.
                // This confirms that fast transfer was executed with correct parameters.
                // Othewise malicious relayer can create a fast transfer with arbitrary high fee and claim it here.
                if fast_transfer_status.finalised {
                    self.remove_fast_transfer(&fast_transfer.id());
                } else {
                    env::panic_str(BridgeError::FastTransferNotFinalised.to_string().as_str());
                }
            }
        }

        let token = self.get_token_id(&transfer_message.token);
        let token_address = self
            .get_token_address(transfer_message.get_destination_chain(), token.clone())
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let denormalized_amount = Self::denormalize_amount(
            fin_transfer.amount.0,
            self.token_decimals
                .get(&token_address)
                .near_expect(BridgeError::TokenDecimalsNotFound),
        );
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L1834-1836)
```rust
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));
```

**File:** near/omni-bridge/src/lib.rs (L1838-1848)
```rust
        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }
```

**File:** near/omni-bridge/src/storage.rs (L186-211)
```rust
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let mut storage = self
            .storage_balance_of(&account_id)
            .near_expect(StorageError::AccountNotRegistered(account_id.clone()));
        let to_withdraw = amount.unwrap_or(storage.available);
        storage.total = storage.total.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.total,
            },
        );
        storage.available = storage.available.checked_sub(to_withdraw).near_expect(
            StorageError::NotEnoughStorageBalance {
                requested: to_withdraw,
                available: storage.available,
            },
        );

        self.accounts_balances.insert(&account_id, &storage);

        Promise::new(account_id).transfer(to_withdraw).detach();

        storage
```
