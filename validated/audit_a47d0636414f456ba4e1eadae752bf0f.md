### Title
Integer Overflow Panic in `check_deposit_msg` Locks Deposited BTC — (`contracts/satoshi-bridge/src/deposit_msg.rs`)

### Summary

`check_deposit_msg` accumulates `post_action.amount.0` into a `u128` before performing the whitelist guard. With `overflow-checks = true` set in the workspace release profile, two `PostAction`s each carrying `amount = u128::MAX` cause an arithmetic panic on the second iteration. Because `check_deposit_msg` is called synchronously inside `internal_verify_deposit` — before any callback is scheduled — the entire `verify_deposit` transaction aborts, no UTXO is stored, and the BTC sent to the deterministically-derived deposit address is locked with no automatic recovery path.

---

### Finding Description

**Root cause — unchecked accumulation before the whitelist guard**

In `check_deposit_msg`, `total_amount` is incremented at the top of the loop body, before the whitelist rejection: [1](#0-0) 

```rust
let mut total_amount = 0;
for (index, post_action) in post_actions.iter().enumerate() {
    total_amount += post_action.amount.0;   // ← overflow here on 2nd iteration
```

The whitelist check that would otherwise reject an invalid action only runs after the accumulation: [2](#0-1) 

With two `PostAction`s each having `amount = u128::MAX`:
- Iteration 1: `total_amount = 0 + u128::MAX` — no overflow, and if the first action's `receiver_id` is whitelisted, execution continues.
- Iteration 2: `total_amount = u128::MAX + u128::MAX` — **wrapping addition panics** under `overflow-checks = true`.

**`overflow-checks = true` is set in the release profile** [3](#0-2) 

```toml
[profile.release]
overflow-checks = true
```

This applies to the WASM build used on-chain.

**`check_deposit_msg` is called synchronously, before any callback** [4](#0-3) 

```rust
let post_actions = self.check_deposit_msg(deposit_msg, mint_amount);
promise.then(
    Self::ext(env::current_account_id())
        ...
        .verify_deposit_callback(...)
)
```

The panic aborts `internal_verify_deposit` before the `verify_deposit_callback` is ever scheduled. Consequently:
- `verified_deposit_utxo` is never updated.
- No UTXO is stored.
- No nBTC is minted.
- The BTC UTXO sits at the deposit address derived from the malicious `DepositMsg` hash.

**Prerequisite: first `PostAction` must pass the whitelist**

The overflow is only reached on the second iteration if the first `PostAction`'s `receiver_id` is on the `post_action_receiver_id_white_list`. Whitelisted addresses (e.g., burrowland) are publicly known protocol configuration, so this prerequisite is satisfiable by any unprivileged user. [5](#0-4) 

**No automatic recovery**

The deposit address is deterministically derived from the `DepositMsg` hash: [6](#0-5) 

The relayer cannot substitute a different `DepositMsg` — the BTC output's `script_pubkey` is checked against the address derived from the exact `DepositMsg` passed to `verify_deposit`. Every retry with the malicious `DepositMsg` panics again. If the attacker omits `refund_address` from the `DepositMsg`, the standard refund path is also unavailable, requiring operator intervention to recover the funds.

---

### Impact Explanation

An unprivileged user can craft a `DepositMsg` with two `PostAction`s each having `amount = u128::MAX`, send real BTC to the derived deposit address, and cause every relayer call to `verify_deposit` for that UTXO to panic. The deposited BTC is locked at the bridge-controlled address with no automatic recovery. This matches the **Medium** impact: attacker-triggered temporary locking of bridged funds requiring operator intervention.

---

### Likelihood Explanation

- The attacker only needs to know one whitelisted `receiver_id` (publicly observable on-chain) and a valid `msg` template for it.
- No privileged access is required; `get_user_deposit_address` is a public view call.
- The attacker must spend real BTC to execute the attack, which limits casual abuse but does not prevent a motivated attacker.

---

### Recommendation

Move the `total_amount` accumulation to after all per-action guards, or use `checked_add` and return `None` on overflow:

```rust
total_amount = total_amount.checked_add(post_action.amount.0).unwrap_or_else(|| {
    Event::InvalidPostAction {
        index: Some(index),
        err_msg: "total amount overflow".to_string(),
    }.emit();
    return_none_flag = true;
    0
});
```

Or more cleanly, restructure the loop so that `total_amount +=` only executes after all guards for that iteration have passed, and use `checked_add` returning `None` on overflow.

---

### Proof of Concept

```rust
// Unit test: assert check_deposit_msg returns None rather than panicking
#[test]
fn test_overflow_two_max_amount_post_actions() {
    let mut unit_env = init_unit_env();
    // First post_action uses a whitelisted receiver_id so iteration 1 passes
    let result = unit_env.contract.check_deposit_msg(
        DepositMsg {
            recipient_id: recipient_id(),
            post_actions: Some(vec![
                PostAction {
                    receiver_id: burrowland_id(), // whitelisted
                    amount: U128(u128::MAX),
                    memo: None,
                    msg: String::new(),
                    gas: None,
                },
                PostAction {
                    receiver_id: burrowland_id(), // whitelisted
                    amount: U128(u128::MAX),
                    memo: None,
                    msg: String::new(),
                    gas: None,
                },
            ]),
            extra_msg: None,
            safe_deposit: None,
            refund_address: None,
        },
        u128::MAX,
    );
    // Currently panics with overflow; should return None
    assert!(result.is_none());
}
```

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L83-85)
```rust
        let mut total_amount = 0;
        for (index, post_action) in post_actions.iter().enumerate() {
            total_amount += post_action.amount.0;
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L90-116)
```rust
            if post_action.receiver_id == env::current_account_id() {
                Event::InvalidPostAction {
                    index: Some(index),
                    err_msg: format!(
                        "The receiver_id({}) of the post_action cannot be the bridge itself.",
                        post_action.receiver_id
                    ),
                }
                .emit();
                return None;
            }
            // The receiver_id must be on the whitelist.
            if !self
                .data()
                .post_action_receiver_id_white_list
                .contains(&post_action.receiver_id)
            {
                Event::InvalidPostAction {
                    index: Some(index),
                    err_msg: format!(
                        "The receiver_id({}) of the post_action is not on the whitelist.",
                        post_action.receiver_id
                    ),
                }
                .emit();
                return None;
            }
```

**File:** Cargo.toml (L21-27)
```text
[profile.release]
codegen-units = 1
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L58-70)
```rust
            let post_actions = self.check_deposit_msg(deposit_msg, mint_amount);
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_deposit_callback(
                        recipient_id,
                        mint_amount.into(),
                        protocol_fee.into(),
                        relayer_fee.into(),
                        pending_utxo_info,
                        post_actions,
                    ),
            )
```
