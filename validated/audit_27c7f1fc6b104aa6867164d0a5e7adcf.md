### Title
`is_structure_equal` treats all template fields as optional, allowing `{}` to match any registered template — (`contracts/satoshi-bridge/src/json_utils.rs`)

### Summary

`is_structure_equal` in `json_utils.rs` implements a "fields are optional" rule that causes an empty JSON object `{}` to match every non-empty template. Any unprivileged depositor can therefore set `post_action.msg = "{}"` and pass the template-conformance check in `check_deposit_msg`, forwarding an empty-object msg to a whitelisted receiver via `ft_transfer_call`, in violation of the invariant that the msg must structurally conform to an approved template.

### Finding Description

`is_structure_equal` iterates over the **template's** keys and only recurses when the corresponding key is **present** in the input: [1](#0-0) 

```rust
(Value::Object(t_obj), Value::Object(i_obj)) => {
    for (key, t_val) in t_obj {
        if let Some(i_val) = i_obj.get(key) {   // ← skipped when key absent
            if !is_structure_equal(t_val, i_val) {
                return false;
            }
        }
        // no else-branch → missing key is silently accepted
    }
    for key in i_obj.keys() {                   // vacuous when i_obj is empty
        if !t_obj.contains_key(key) {
            return false;
        }
    }
    true
}
```

When `input = {}`:
- Loop 1 iterates over every template key, but `i_obj.get(key)` always returns `None` → the inner block is never entered → no `false` is returned.
- Loop 2 iterates over `i_obj.keys()` which is empty → vacuous → no `false` is returned.
- Function returns `true`.

This is consistent with the documented rule 1 in the same file: [2](#0-1) 

> `input` may omit fields defined in the `template` (treated as optional).

That design choice makes every template field optional, so `{}` is a valid "subset" of any template.

### Impact Explanation

`check_deposit_msg` calls `is_structure_equal` to gate whether a `post_action.msg` is allowed: [3](#0-2) 

When the check passes, the `post_actions` vector (containing the attacker-supplied `msg: "{}"`) is returned and forwarded through `internal_mint_promise` → `ext_nbtc::mint` → `ft_transfer_call` to the whitelisted receiver: [4](#0-3) 

The whitelisted receiver's `ft_on_transfer` receives `{}` instead of the operator-approved structured msg. Depending on the receiver's implementation this can:
- Cause the receiver to panic/revert (stuck or failed transfer requiring operator intervention).
- Be silently accepted if the receiver treats missing fields as defaults, triggering unintended downstream logic.

In either case the msg-template safety guarantee — the only mechanism preventing arbitrary msg content from reaching whitelisted receivers — is completely bypassed.

### Likelihood Explanation

The path is fully public: any depositor who knows a whitelisted `receiver_id` has templates registered can craft a valid BTC deposit with `post_actions[0].msg = "{}"`. No privileged role, leaked key, or external dependency is required. The deposit address is deterministically derived from the `DepositMsg` hash, so the attacker simply sends BTC to the address computed from their crafted msg. [5](#0-4) 

### Recommendation

Remove the "optional field" semantics for security-sensitive template matching. When a template key is absent from the input, the check should **fail**, not silently pass:

```rust
for (key, t_val) in t_obj {
    match i_obj.get(key) {
        Some(i_val) => {
            if !is_structure_equal(t_val, i_val) {
                return false;
            }
        }
        None => return false,  // required field missing → reject
    }
}
```

If optional fields are genuinely needed, encode that intent explicitly in the template (e.g., wrap the value in a `null`-typed sentinel as already supported by rule 5). [6](#0-5) 

### Proof of Concept

```rust
use serde_json::{json, Value};

fn is_structure_equal(template: &Value, input: &Value) -> bool {
    // ... (copy of production implementation) ...
}

#[test]
fn empty_object_bypasses_any_template() {
    let template = json!({"action": "string", "amount": 0});
    let input    = json!({});
    // Currently returns true — should return false
    assert!(!is_structure_equal(&template, &input),
        "BUG: empty object matched a non-empty template");
}
```

Running this test against the current `json_utils.rs` implementation will **fail** (the assertion fires), confirming that `is_structure_equal` returns `true` for `{}` against any non-empty template. [7](#0-6)

### Citations

**File:** contracts/satoshi-bridge/src/json_utils.rs (L7-8)
```rust
/// 1. `input` may omit fields defined in the `template` (treated as optional).
/// 2. `input` must not contain extra fields not present in the `template`.
```

**File:** contracts/satoshi-bridge/src/json_utils.rs (L14-31)
```rust
pub fn is_structure_equal(template: &Value, input: &Value) -> bool {
    match (template, input) {
        (Value::Object(t_obj), Value::Object(i_obj)) => {
            for (key, t_val) in t_obj {
                if let Some(i_val) = i_obj.get(key) {
                    if !is_structure_equal(t_val, i_val) {
                        return false;
                    }
                }
            }
            // The input must not contain fields that are not defined in the template.
            for key in i_obj.keys() {
                if !t_obj.contains_key(key) {
                    return false;
                }
            }
            true
        }
```

**File:** contracts/satoshi-bridge/src/json_utils.rs (L53-53)
```rust
        (Value::Null, _) => true, // When a key’s value is not restricted, set its value to null.
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
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

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L19-28)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .mint(
                recipient_id.clone(),
                mint_amount,
                protocol_fee,
                env::signer_account_id(),
                relayer_fee,
                post_actions,
            )
```
