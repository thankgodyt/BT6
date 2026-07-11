### Title
`is_structure_equal` Vacuous-Loop Allows Empty Input Array to Match Any Non-Empty Template Array — (`contracts/satoshi-bridge/src/json_utils.rs`)

---

### Summary

The `Array` branch of `is_structure_equal` contains a logic gap: when the template array is non-empty but the input array is empty, the validation loop iterates zero times and falls through to `true`. This lets an unprivileged depositor supply a `post_action.msg` whose array fields are empty `[]` while the DAO-registered template requires non-empty arrays, bypassing the msg-template restriction entirely.

---

### Finding Description

In `contracts/satoshi-bridge/src/json_utils.rs`, the `Array` branch reads:

```rust
(Value::Array(t_arr), Value::Array(i_arr)) => {
    if t_arr.is_empty() {
        return i_arr.is_empty();   // ← only guards the empty-template case
    }
    for i_item in i_arr {          // ← zero iterations when i_arr is empty
        ...
        if !matched { return false; }
    }
    true                           // ← reached unconditionally when i_arr is []
}
``` [1](#0-0) 

The guard on line 33 only handles the case where the **template** array is empty. When the template array is non-empty and the input array is empty, the `for i_item in i_arr` loop has zero iterations, so `!matched` is never evaluated, and the function returns `true`.

`check_deposit_msg` calls `is_structure_equal` to validate `post_action.msg` against every registered template:

```rust
let is_match = match serde_json::from_str::<Value>(&post_action.msg) {
    Ok(msg_value) => msg_templates.iter().any(|template| {
        match serde_json::from_str::<Value>(template) {
            Ok(template_value) => is_structure_equal(&template_value, &msg_value),
            ...
        }
    }),
    ...
};
``` [2](#0-1) 

If `is_structure_equal` returns `true`, the post-action is accepted and the raw `msg` string is forwarded to the receiver via `ft_on_transfer` in `handle_post_action`: [3](#0-2) 

---

### Impact Explanation

The msg-template system is the bridge's policy control over what instructions a depositor may send to a whitelisted receiver. An attacker can submit a `post_action.msg` like `{"Execute":{"actions":[]}}` against a template of `{"Execute":{"actions":[{"IncreaseCollateral":{...}}]}}`. The template check passes, and the structurally non-conforming message is forwarded to the receiver. The receiver (e.g., Burrowland) receives an empty `actions` list instead of the required action type, which can trigger unexpected behavior — a no-op that silently swallows the user's nBTC transfer, a panic that causes the `ft_resolve_transfer` callback to return funds to the wrong account, or any other receiver-specific edge case. This is a **bypass of bridge limits or policies** (Medium).

---

### Likelihood Explanation

The precondition is only that the DAO has registered at least one JSON template containing a non-empty array for a whitelisted receiver — the exact configuration shown in the existing unit tests (`{"Execute":{"actions":[{"IncreaseCollateral":...}]}}`). [4](#0-3) 

Any unprivileged depositor can then craft a BTC deposit with the bypassing `msg`. No privileged access, leaked key, or operator cooperation is required.

---

### Recommendation

Add an explicit check in the `Array` branch: if the template array is non-empty, the input array must also be non-empty before the loop runs.

```rust
(Value::Array(t_arr), Value::Array(i_arr)) => {
    if t_arr.is_empty() {
        return i_arr.is_empty();
    }
    if i_arr.is_empty() {   // ← add this guard
        return false;
    }
    for i_item in i_arr {
        ...
    }
    true
}
``` [1](#0-0) 

---

### Proof of Concept

Unit-test (no privileged setup beyond the DAO registering a template, which is the normal deployment state):

```rust
use near_sdk::serde_json::{from_str, Value};
use crate::json_utils::is_structure_equal;

#[test]
fn test_empty_input_array_must_not_match_nonempty_template_array() {
    let template: Value = from_str(r#"{"actions":[{"type":""}]}"#).unwrap();
    let input:    Value = from_str(r#"{"actions":[]}"#).unwrap();
    // BUG: currently returns true — should return false
    assert!(!is_structure_equal(&template, &input));
}
```

With the current code the assertion **fails** (the function returns `true`), confirming the bypass. The full deposit path through `check_deposit_msg` → `internal_verify_deposit` → `handle_post_action` → `ft_on_transfer` then forwards the empty-actions message to the whitelisted receiver. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/json_utils.rs (L32-48)
```rust
        (Value::Array(t_arr), Value::Array(i_arr)) => {
            if t_arr.is_empty() {
                return i_arr.is_empty();
            }
            for i_item in i_arr {
                let mut matched = false;
                for t_item in t_arr {
                    if is_structure_equal(t_item, i_item) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return false;
                }
            }
            true
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L117-143)
```rust
            if let Some(msg_templates) = self
                .data()
                .post_action_msg_templates
                .get(&post_action.receiver_id)
            {
                let is_match =
                    match serde_json::from_str::<Value>(&post_action.msg) {
                        Ok(msg_value) => msg_templates.iter().any(|template| {
                            match serde_json::from_str::<Value>(template) {
                                Ok(template_value) => {
                                    is_structure_equal(&template_value, &msg_value)
                                }
                                Err(_) => false,
                            }
                        }),
                        Err(_) => msg_templates
                            .iter()
                            .any(|template| template == &post_action.msg),
                    };
                if !is_match {
                    Event::InvalidPostAction {
                        index: Some(index),
                        err_msg: "Unsupported post_action.msg.".to_string(),
                    }
                    .emit();
                    return None;
                }
```

**File:** contracts/nbtc/src/lib.rs (L408-411)
```rust
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas)
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
```

**File:** contracts/satoshi-bridge/src/unit/post_action.rs (L483-486)
```rust
    unit_env.contract.extend_post_action_msg_templates(
        burrowland_id(),
        HashSet::from([r#"{"Execute":{"actions":[{"IncreaseCollateral":{"token_id":"", "amount":"", "max_amount":""}}]}}"#.to_string()]),
    );
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
