All code references check out. The vulnerability is confirmed:

1. The short-circuit OR at lines 566–581 is exactly as described — `NativeFeeRestricted` check is only in Branch 2.
2. `try_to_transfer_balance_from_message_account` (lines 260–290) contains no role check.
3. `TransferMessageStorageAccount` (lines 599–634) excludes `origin_nonce` and `destination_nonce`, making the account ID fully deterministic pre-transfer.
4. `storage_deposit` (lines 140–169) accepts any `account_id` with no caller restrictions.
5. `init_transfer_resume` (lines 635–645) also calls `try_to_transfer_balance_from_message_account` without a role check.

---

Audit Report

## Title
`NativeFeeRestricted` Role Bypass via Pre-Deposit to Deterministic Message Storage Account — (`near/omni-bridge/src/lib.rs`)

## Summary
The `NativeFeeRestricted` role check in `init_transfer` is placed exclusively in the second branch of a short-circuit `||` condition. An account holding the `NativeFeeRestricted` role can force the first branch (`try_to_transfer_balance_from_message_account`) to return `Ok` by pre-depositing NEAR to the deterministically computable message storage account, causing the role check to be skipped entirely and allowing a transfer with a non-zero `native_token_fee` to proceed.

## Finding Description
In `near/omni-bridge/src/lib.rs` at lines 566–581, the storage-payer selection logic is a short-circuit OR:

```rust
if self
    .try_to_transfer_balance_from_message_account(   // Branch 1 — no role check
        &message_storage_account_id,
        NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
        &signer_id,
        required_storage_balance,
    )
    .is_ok()
    || (self.has_storage_balance(...)                 // Branch 2 — role check here
        && (init_transfer_msg.native_token_fee.0 == 0
            || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
```

`try_to_transfer_balance_from_message_account` (`near/omni-bridge/src/storage.rs`, lines 260–290) contains no role check. It returns `Ok` when: (1) `message_storage_account_id` is registered in `accounts_balances` with `total >= native_fee`; (2) `signer_id` is registered in `accounts_balances`; and (3) combined available balance covers `required_storage_payer_balance + native_fee`.

The `message_storage_account_id` is a SHA-256 hash of `TransferMessageStorageAccount { token, amount, recipient, fee, sender, msg }` plus optional `external_id`. As confirmed by the `From<TransferMessage>` impl at lines 623–634 of `near/omni-types/src/lib.rs`, `origin_nonce` and `destination_nonce` are excluded from the struct, making the account ID fully predictable before the transfer is submitted.

`storage_deposit` (`near/omni-bridge/src/storage.rs`, lines 140–169) accepts any `account_id` with no caller restrictions, allowing anyone to register and fund any account ID.

The same gap exists in `init_transfer_resume` (lines 635–645), which calls `try_to_transfer_balance_from_message_account` without a role check. A `NativeFeeRestricted` account that deposits to the message account after yielding would also bypass the check there.

## Impact Explanation
This is a role bypass under the Critical impact category: "Unauthorized transaction, authorization bypass, role bypass… that lets an attacker execute bridge… actions." An account granted `NativeFeeRestricted` can initiate transfers with an arbitrary non-zero `native_token_fee`, completely circumventing the intended access control restriction. The `NativeFeeRestricted` role is a protocol-enforced constraint on certain accounts; bypassing it undermines the protocol's fee-control guarantees.

## Likelihood Explanation
The exploit requires only two public contract calls (`storage_deposit` twice, then `ft_transfer_call`) and offline computation of a SHA-256 hash. No privileged access beyond holding the `NativeFeeRestricted` role itself is needed. The message account ID is deterministic and computable by any party with knowledge of the planned transfer parameters. Any account that has been assigned the restricted role and is motivated to circumvent it can execute this bypass repeatably.

## Recommendation
Move the `NativeFeeRestricted` check to a position that is evaluated unconditionally whenever `native_token_fee > 0`, regardless of which storage-payment branch is taken. Add an early guard at the top of `init_transfer`:

```rust
require!(
    init_transfer_msg.native_token_fee.0 == 0
        || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone()),
    BridgeError::NativeFeeRestricted.as_ref()
);
```

Apply the same fix to `init_transfer_resume` by checking the role before calling `try_to_transfer_balance_from_message_account`.

## Proof of Concept
```rust
// 1. Admin grants NativeFeeRestricted to attacker
contract.acl_grant_role("NativeFeeRestricted", attacker_id);

// 2. Attacker computes the message storage account ID offline
let storage_account = TransferMessageStorageAccount {
    token: OmniAddress::Near(token_id.clone()),
    amount: U128(transfer_amount),
    recipient: eth_recipient.clone(),
    fee: Fee { fee: U128(0), native_fee: U128(native_fee_amount) },
    sender: OmniAddress::Near(attacker_id.clone()),
    msg: String::new(),
};
let message_account_id = storage_account.id(None); // deterministic, no nonces

// 3. Attacker pre-deposits to the message storage account
attacker.call(bridge, "storage_deposit")
    .args_json(json!({ "account_id": message_account_id }))
    .deposit(min_account_storage + native_fee_amount + required_transfer_storage)
    .transact();

// 4. Attacker registers themselves
attacker.call(bridge, "storage_deposit")
    .args_json(json!({ "account_id": attacker_id }))
    .deposit(min_account_storage)
    .transact();

// 5. Attacker initiates transfer with non-zero native_token_fee
attacker.call(token, "ft_transfer_call")
    .args_json(json!({
        "receiver_id": bridge,
        "amount": U128(transfer_amount),
        "msg": json!({ "native_token_fee": U128(native_fee_amount), ... })
    }))
    .transact();

// Result: try_to_transfer_balance_from_message_account returns Ok,
// NativeFeeRestricted check at line 579-580 is never reached,
// transfer proceeds with native_token_fee > 0.
// Assert: InitTransferEvent emitted with fee.native_fee == native_fee_amount
```