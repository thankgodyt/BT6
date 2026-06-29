### Title
`NativeFeeRestricted` Role Bypass via `update_transfer_fee` — (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `NativeFeeRestricted` role is enforced in `init_transfer` to prevent designated accounts from setting a non-zero native fee. However, `update_transfer_fee` — which modifies the fee on an already-stored pending transfer — performs no equivalent role check. A restricted account can trivially bypass the restriction by initiating a transfer with `native_token_fee = 0`, then calling `update_transfer_fee` to raise the native fee to any desired value.

---

### Finding Description

**Restriction in `init_transfer`:**

In `near/omni-bridge/src/lib.rs`, the direct-execution branch of `init_transfer` gates on:

```rust
(init_transfer_msg.native_token_fee.0 == 0
    || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()))
``` [1](#0-0) 

This means: if the caller holds the `NativeFeeRestricted` role **and** specifies a non-zero `native_token_fee`, the direct path is blocked.

**No equivalent check in `update_transfer_fee`:**

`update_transfer_fee` validates only that:
- The transfer has no `origin_transfer_id`
- The new token fee is ≥ current and < amount
- Only the original sender can raise the token fee
- The attached NEAR deposit equals the native fee delta [2](#0-1) 

There is **no check** for `Role::NativeFeeRestricted` anywhere in `update_transfer_fee`. The function freely accepts a native fee increase from any caller, including those the DAO has explicitly restricted.

**Bypass sequence:**

1. Restricted account calls `ft_transfer_call` → `init_transfer` with `native_token_fee = 0`. The restriction check passes because `native_token_fee.0 == 0`.
2. The transfer is stored in `pending_transfers` with `fee.native_fee = 0`.
3. Restricted account calls `update_transfer_fee(transfer_id, UpdateFee::Fee(Fee { fee: ..., native_fee: X }))` with `X > 0` and attaches `X` yoctoNEAR.
4. `update_transfer_fee` accepts the update — no role check — and the stored transfer now carries a non-zero native fee.
5. When `sign_transfer` is called and the transfer is finalised, the relayer receives the native fee as if the restriction never existed.

---

### Impact Explanation

The `NativeFeeRestricted` role is an explicit DAO-controlled access-control mechanism. Its bypass is a **role/authorization bypass** — one of the explicitly listed critical impact categories. A restricted account can set arbitrary native fees on its outbound transfers, fully circumventing the DAO's policy enforcement. This undermines the integrity of the access-control system and allows a restricted actor to manipulate relayer incentives in ways the protocol operators explicitly prohibited.

---

### Likelihood Explanation

The bypass requires no special privileges, no flash loans, and no external dependencies. Any account that holds the `NativeFeeRestricted` role can execute it in two sequential, publicly callable transactions. Likelihood is **high**.

---

### Recommendation

Add a `NativeFeeRestricted` role check inside `update_transfer_fee` whenever the native fee is being increased. Specifically, when `diff_native_fee > 0`, verify that the predecessor does not hold `Role::NativeFeeRestricted`:

```rust
if diff_native_fee > 0 {
    require!(
        !self.acl_has_role(
            Role::NativeFeeRestricted.into(),
            env::predecessor_account_id()
        ),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}
```

This mirrors the guard already present in `init_transfer` and closes the inconsistency between the two code paths.

---

### Proof of Concept

```
1. DAO grants NativeFeeRestricted to account "restricted.near".

2. "restricted.near" calls:
     token.ft_transfer_call(
         receiver_id: "omni.bridge.near",
         amount: 1000,
         msg: InitTransferMsg { native_token_fee: 0, fee: 10, recipient: "0x...", ... }
     )
   → init_transfer passes because native_token_fee == 0.
   → Transfer stored with fee = { fee: 10, native_fee: 0 }.

3. "restricted.near" calls:
     omni.bridge.near.update_transfer_fee(
         transfer_id: <id from step 2>,
         fee: UpdateFee::Fee(Fee { fee: 10, native_fee: 1_000_000_000_000_000_000_000_000 })
     )
     attached_deposit: 1_000_000_000_000_000_000_000_000 yoctoNEAR

   → No NativeFeeRestricted check → update accepted.
   → Transfer now carries native_fee = 1 NEAR.

4. Relayer calls sign_transfer and finalises the transfer.
   → Relayer receives 1 NEAR native fee, bypassing the DAO restriction entirely.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L388-435)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L574-581)
```rust
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
```
