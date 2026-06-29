### Title
Missing `assert_one_yocto()` in `update_transfer_fee` Allows Function Call Key to Drain User's Pending Transfer — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`update_transfer_fee` is a `#[payable]` public function callable by any user that modifies the token fee on a pending transfer. It lacks `assert_one_yocto()`, so when the native-fee delta is zero (requiring 0 NEAR deposit), a NEAR Function Call key — which websites store after a user signs in — can invoke it without the user's Full Access key. A malicious or compromised website can use this key to silently inflate the token fee on the user's pending transfer to just below the full transfer amount, redirecting nearly all bridged tokens to the relayer as fee.

---

### Finding Description

NEAR's Function Call keys can only call contract methods that do **not** attach NEAR as a deposit. `update_transfer_fee` is `#[payable]` but enforces the deposit constraint dynamically: [1](#0-0) 

```rust
#[payable]
#[pause]
pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
    match fee {
        UpdateFee::Fee(fee) => {
            ...
            require!(
                fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                BridgeError::InvalidFee.as_ref()
            );
            require!(
                fee.fee == current_fee.fee
                    || OmniAddress::Near(env::predecessor_account_id())
                        == transfer.message.sender,
                BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
            );
            let diff_native_fee = fee
                .native_fee.0
                .checked_sub(current_fee.native_fee.0)
                .near_expect(BridgeError::LowerFee);
            require!(
                NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                BridgeError::InvalidAttachedDeposit.as_ref()
            );
``` [2](#0-1) 

When an attacker keeps `fee.native_fee` equal to `current_fee.native_fee`, `diff_native_fee` is `0`, so `env::attached_deposit()` must be `0`. A Function Call key **can** make a zero-deposit call, bypassing the Full Access key requirement entirely. There is no `assert_one_yocto()` guard to prevent this.

The only other guard is the sender check (line 404–408), which passes because the Function Call key acts as the user's own account (`env::predecessor_account_id() == transfer.message.sender`).

The fee ceiling is `fee.fee < transfer.message.amount`, so the attacker can set `fee.fee = transfer.message.amount - 1`, leaving the recipient with 1 token unit while the relayer collects the rest as fee. [3](#0-2) 

---

### Impact Explanation

After the fee is inflated, the relayer calls `sign_transfer`, which computes `amount_without_fee` and signs a payload delivering that dust amount to the destination chain. The user's bridged tokens (NEAR-side NEP-141 tokens already locked/burned in `init_transfer_internal`) are effectively stolen: the relayer receives `transfer.amount - 1` as fee, and the user receives `1` unit on the destination chain. [4](#0-3) 

This constitutes **unauthorized balance manipulation / fee mis-accounting** that changes user balances — a critical impact under the allowed scope.

---

### Likelihood Explanation

The attack requires:
1. The user has previously signed in to any website that requested a Function Call key for the omni-bridge contract (standard dApp onboarding).
2. That website is malicious or later compromised.
3. The user has a pending transfer (i.e., has called `ft_transfer_call` with an `InitTransfer` message).

All three conditions are realistic for a bridge with active users. The attacker does not need admin access, leaked keys, or MPC compromise.

---

### Recommendation

Add `assert_one_yocto()` at the top of `update_transfer_fee`, and mark it `#[payable]` with a required 1 yoctoNEAR deposit, consistent with the pattern already used in `storage_withdraw` and `storage_unregister`: [5](#0-4) 

```rust
#[payable]
#[pause]
pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
    assert_one_yocto();
    // ... existing logic, adjusting diff_native_fee check to account for the 1 yocto
```

The `diff_native_fee` attachment check must then be adjusted to subtract the mandatory 1 yoctoNEAR from `env::attached_deposit()` before comparing, or the fee-update deposit logic must be restructured to treat the 1 yocto separately.

---

### Proof of Concept

1. User signs in to `bridge-dapp.example` → browser stores a Function Call key for `omni-bridge.near` on the user's NEAR account.
2. User calls `ft_transfer_call` on their NEP-141 token contract, sending 1,000,000 tokens to `omni-bridge.near` with `msg = InitTransferMsg { recipient: "eth:0xVictim", fee: { fee: 0, native_fee: 0 }, ... }`. Transfer is stored with `transfer_id = T`.
3. Malicious website (or compromised `bridge-dapp.example`) uses the stored Function Call key to call:
   ```json
   {
     "method": "update_transfer_fee",
     "args": {
       "transfer_id": T,
       "fee": { "Fee": { "fee": "999999", "native_fee": "0" } }
     },
     "deposit": "0"
   }
   ```
   - `diff_native_fee = 0 - 0 = 0` → `attached_deposit == 0` ✓
   - `predecessor == sender` ✓
   - `999999 >= 0 && 999999 < 1000000` ✓
   - No `assert_one_yocto()` → call succeeds with a Function Call key.
4. Relayer calls `sign_transfer(T, ...)`. `amount_without_fee = 1,000,000 - 999,999 = 1`. MPC signs a payload for 1 token to `0xVictim`.
5. On the destination chain, `finTransfer` delivers 1 token unit to the user. The relayer claims 999,999 tokens as fee via `claim_fee`. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L386-436)
```rust
    #[payable]
    #[pause]
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L444-521)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };

        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

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
    }
```

**File:** near/omni-bridge/src/storage.rs (L186-189)
```rust
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
```
