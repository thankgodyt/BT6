### Title
`NativeFeeRestricted` Role Bypass via Message-Account Pre-funding and Yield-Path Resume — (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `NativeFeeRestricted` role check in `init_transfer` is only evaluated in one branch of a short-circuit OR condition. A restricted account can bypass it entirely by pre-funding the deterministic message-storage account before calling `ft_transfer_call`, causing `try_to_transfer_balance_from_message_account` to succeed and short-circuit past the role check. A second bypass exists in `init_transfer_resume`, which is the yield-path callback and contains no `NativeFeeRestricted` check at all.

### Finding Description

In `ft_on_transfer`, the bridge uses `signer_id = env::signer_account_id()` (not the spoofable `sender_id`) to enforce the `NativeFeeRestricted` role: [1](#0-0) 

The role check lives inside `init_transfer` as the **second** operand of a short-circuit OR: [2](#0-1) 

The full condition is:

```
if try_to_transfer_balance_from_message_account(...).is_ok()   // ← first operand
   || (has_storage_balance(...) && (native_fee == 0 || !NativeFeeRestricted))  // ← second operand
```

If the **first operand** evaluates to `Ok`, Rust short-circuits and the `NativeFeeRestricted` check in the second operand is **never evaluated**. The first operand succeeds whenever the virtual message-storage account already holds enough balance.

The message-storage account ID is deterministic and computable before the transfer is submitted: [3](#0-2) 

Any account — including the restricted account itself — can call `storage_deposit` on that virtual account ID at any time. Once pre-funded, `try_to_transfer_balance_from_message_account` returns `Ok`, the fast path is taken, and the transfer with `native_fee > 0` is accepted without ever consulting the role.

A second, independent bypass exists in `init_transfer_resume`, the yield-path callback: [4](#0-3) 

`init_transfer_resume` contains **no** `NativeFeeRestricted` check. A restricted account that lacks pre-funded storage can still bypass the restriction by: (1) submitting `ft_transfer_call` with `native_fee > 0` (the transfer yields because the role check blocks the fast path), then (2) depositing to the message account after the fact, which triggers `init_transfer_resume` and completes the transfer without any role enforcement.

### Impact Explanation

The `NativeFeeRestricted` role is the protocol's mechanism to prevent designated accounts from attaching native-token fees to outbound transfers. Bypassing it allows a restricted account to:

- Set an arbitrary `native_fee` on a NEAR-origin transfer, causing the bridge to pay that amount in NEAR to the relayer's `fee_recipient` from the bridge's own balance (funded by the attacker's pre-deposit).
- Circumvent an admin-imposed restriction that was presumably applied for a security or compliance reason (e.g., preventing a flagged account from incentivising relayers or manipulating the fee market).

This is a concrete role-bypass with a reachable, unprivileged entry path (`ft_transfer_call` → `ft_on_transfer`).

### Likelihood Explanation

The message-storage account ID is fully deterministic from public transfer parameters. Any restricted account can compute it off-chain, call `storage_deposit` on it, and then submit the transfer. No special privileges, no cooperation from third parties, and no timing constraints are required. The yield-path variant requires only two sequential transactions.

### Recommendation

1. **Fast-path fix**: Add the `NativeFeeRestricted` check as an additional guard even when `try_to_transfer_balance_from_message_account` succeeds:

```rust
if (try_to_transfer_balance_from_message_account(...).is_ok()
    && (native_fee == 0 || !acl_has_role(NativeFeeRestricted, signer_id)))
   || (has_storage_balance(...) && (native_fee == 0 || !acl_has_role(NativeFeeRestricted, signer_id)))
```

2. **Yield-path fix**: Add the same role check at the top of `init_transfer_resume` before calling `init_transfer_internal`. Since `storage_owner` is the original `signer_id`, the check is `!acl_has_role(NativeFeeRestricted, storage_owner) || native_fee == 0`.

### Proof of Concept

1. Admin grants `NativeFeeRestricted` to account **A**.
2. **A** computes the deterministic message-storage account ID for a transfer with `native_fee = X > 0`.
3. **A** calls `storage_deposit` on that virtual account ID, depositing enough to cover storage + native fee.
4. **A** calls `ft_transfer_call` on the token contract with `native_token_fee = X`.
5. Inside `ft_on_transfer` → `init_transfer`, `try_to_transfer_balance_from_message_account` returns `Ok` (pre-funded in step 3).
6. The OR short-circuits; the `NativeFeeRestricted` check is never reached.
7. `init_transfer_internal` is called; the transfer is stored with `fee.native_fee = X`.
8. A relayer calls `sign_transfer`; the MPC signs the payload; the relayer later calls `claim_fee`, receiving `X` NEAR — a payment the protocol explicitly intended to forbid for account **A**.

### Citations

**File:** near/omni-bridge/src/lib.rs (L259-263)
```rust
        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
```

**File:** near/omni-bridge/src/lib.rs (L562-563)
```rust
        let message_storage_account_id = transfer_message
            .calculate_storage_account_id(init_transfer_msg.external_id.map(String::from));
```

**File:** near/omni-bridge/src/lib.rs (L566-584)
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
            )
```

**File:** near/omni-bridge/src/lib.rs (L621-646)
```rust
    #[private]
    #[allow(clippy::needless_pass_by_value)]
    pub fn init_transfer_resume(
        &mut self,
        transfer_message: TransferMessage,
        message_storage_account_id: AccountId,
        storage_owner: AccountId,
        #[callback_result] response: Result<(), PromiseError>,
    ) -> U128 {
        self.remove_promise(&message_storage_account_id);
        if response.is_err() {
            env::log_str("Init transfer resume timeout");
        }

        if let Err(err) = self.try_to_transfer_balance_from_message_account(
            &message_storage_account_id,
            NearToken::from_yoctonear(transfer_message.fee.native_fee.0),
            &storage_owner,
            self.required_balance_for_init_transfer_message(transfer_message.clone()),
        ) {
            env::log_str(&format!("Error paying native fee and storage: {err}"));
            return transfer_message.amount;
        }

        self.init_transfer_internal(transfer_message, storage_owner)
    }
```
