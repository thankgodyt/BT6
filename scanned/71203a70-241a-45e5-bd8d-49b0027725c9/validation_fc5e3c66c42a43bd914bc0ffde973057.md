Looking at the exact code paths involved:

### Title
`NativeFeeRestricted` Role Bypass via `update_transfer_fee` — (`near/omni-bridge/src/lib.rs`)

---

### Summary

The `NativeFeeRestricted` role check exists in exactly one location in production code — inside `init_transfer` — and is absent from `update_transfer_fee`. A restricted account can create a transfer with `native_token_fee=0` (bypassing the only guard), then immediately call `update_transfer_fee` to set an arbitrarily large `native_fee`, fully circumventing the role restriction.

---

### Finding Description

The `NativeFeeRestricted` role is enforced in a single conditional branch inside `init_transfer`: [1](#0-0) 

The condition short-circuits when `native_token_fee.0 == 0`, so a restricted account can always create a pending transfer with zero native fee. The role is never checked again anywhere in the contract — confirmed by the fact that `NativeFeeRestricted` appears in only two places in `lib.rs`: the `Role` enum definition and this single guard.

`update_transfer_fee` applies no role check whatsoever: [2](#0-1) 

Its only guards are:
- `origin_transfer_id.is_none()` (line 393)
- `fee.fee >= current_fee.fee` (line 400)
- `fee.fee == current_fee.fee || predecessor == sender` (line 404–408) — governs the *token* fee only
- `diff_native_fee == attached_deposit` (line 417–419) — requires the caller to fund the increase

None of these prevent a `NativeFeeRestricted` account from raising `native_fee` from 0 to any value, provided they attach the corresponding NEAR deposit.

The updated `native_fee` is persisted unconditionally: [3](#0-2) 

And is paid out to the fee recipient through `send_fee_internal` on `claim_fee`: [4](#0-3) 

---

### Impact Explanation

The `NativeFeeRestricted` role is rendered completely ineffective. Any account bearing this role can set an arbitrary non-zero native fee on any transfer it originates, bypassing the sole access-control guard. The role restriction — intended to prevent certain accounts from using native fees — provides zero protection once a transfer is pending.

This is a concrete role bypass: a restricted account executes a bridge action (setting a non-zero native fee) that the access-control system was explicitly designed to prohibit. The NEAR deposited to fund the fee increase is correctly accounted for (the caller pays `diff_native_fee`), so no protocol funds are directly stolen, but the invariant that `NativeFeeRestricted` accounts cannot set non-zero native fees is fully broken.

---

### Likelihood Explanation

The path requires only two sequential public calls (`ft_transfer_call` with `native_token_fee=0`, then `update_transfer_fee` with a higher `native_fee`) from any account that has been granted the `NativeFeeRestricted` role. No privileged access beyond the role itself, no leaked keys, and no external dependencies are needed. It is trivially reproducible on a local sandbox.

---

### Recommendation

Add a `NativeFeeRestricted` role check inside `update_transfer_fee` before accepting any increase to `native_fee`:

```rust
if fee.native_fee.0 > current_fee.native_fee.0 {
    require!(
        !self.acl_has_role(
            Role::NativeFeeRestricted.into(),
            env::predecessor_account_id()
        ),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}
```

This mirrors the guard already present in `init_transfer` and closes the bypass.

---

### Proof of Concept

On a local NEAR sandbox with the unmodified contract:

1. Deploy the contract; grant `NativeFeeRestricted` to `account_a`.
2. `account_a` calls `storage_deposit` with enough NEAR to cover storage + 0 native fee.
3. `account_a` calls `ft_transfer_call` → `init_transfer` with `native_token_fee: U128(0)`. The check at line 579 passes (`native_token_fee.0 == 0`). Transfer is stored with `fee.native_fee = 0`.
4. `account_a` calls `update_transfer_fee(transfer_id, UpdateFee::Fee(Fee { fee: <same token fee>, native_fee: U128(1_000_000_000_000_000_000_000_000) }))` attaching `1e24` yoctoNEAR. No role check fires; the transfer is updated with `native_fee = 1e24`.
5. A relayer calls `sign_transfer`; `sign_transfer_callback` logs the `SignTransferEvent`.
6. The relayer calls `claim_fee`; `send_fee_internal` executes `Promise::new(fee_recipient).transfer(1e24 yoctoNEAR)`.
7. Assert: the relayer's balance increased by `1e24` yoctoNEAR — the native fee that `account_a` was prohibited from setting has been successfully set and paid out.

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

**File:** near/omni-bridge/src/lib.rs (L574-580)
```rust
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
```

**File:** near/omni-bridge/src/lib.rs (L2664-2667)
```rust
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
```
