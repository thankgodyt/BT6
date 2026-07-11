### Title
`is_structure_equal` treats all template fields as optional, allowing `{}` to match any object template — (`contracts/satoshi-bridge/src/json_utils.rs`)

### Summary

The `is_structure_equal` function is documented to treat template fields as optional (Rule 1 in its docstring). As a consequence, an empty JSON object `{}` structurally matches **any** JSON-object template, because the first loop over template keys finds no corresponding input keys and silently skips them, and the second loop over input keys is vacuously empty. This allows an unprivileged depositor to supply `post_action.msg = "{}"` and pass the `check_deposit_msg` template guard for any whitelisted receiver that has at least one JSON-object template registered.

### Finding Description

**Root cause — `is_structure_equal` (`json_utils.rs` lines 16–31):**

```rust
(Value::Object(t_obj), Value::Object(i_obj)) => {
    for (key, t_val) in t_obj {
        if let Some(i_val) = i_obj.get(key) {   // ← None when i_obj is empty; skipped
            if !is_structure_equal(t_val, i_val) {
                return false;
            }
        }
    }
    for key in i_obj.keys() {                   // ← vacuously empty; skipped
        if !t_obj.contains_key(key) {
            return false;
        }
    }
    true                                         // ← always reached for input={}
}
``` [1](#0-0) 

When `input = {}`, the first loop finds no keys in `i_obj` to look up, so no `return false` is ever reached. The second loop is vacuously empty. The function returns `true` regardless of how deeply nested the template is.

**Template check in `check_deposit_msg` (`deposit_msg.rs` lines 117–143):**

```rust
if let Some(msg_templates) = self.data().post_action_msg_templates.get(&post_action.receiver_id) {
    let is_match = match serde_json::from_str::<Value>(&post_action.msg) {
        Ok(msg_value) => msg_templates.iter().any(|template| {
            match serde_json::from_str::<Value>(template) {
                Ok(template_value) => is_structure_equal(&template_value, &msg_value),
                Err(_) => false,
            }
        }),
        ...
    };
    if !is_match { return None; }
}
``` [2](#0-1) 

When `post_action.msg = "{}"`, `serde_json::from_str` succeeds with `Value::Object({})`. For every registered JSON-object template (e.g., `{"Execute":{"actions":[{"IncreaseCollateral":{"token_id":"","amount":""}}]}}`), `is_structure_equal` returns `true`. `is_match` becomes `true`, the guard passes, and `check_deposit_msg` returns `Some(post_actions)` containing the empty-object msg.

**Execution path:**

`internal_verify_deposit_entry` → `internal_verify_deposit` → `check_deposit_msg` (passes) → `verify_deposit_callback` → `internal_mint_promise` → `ft_transfer_call` to whitelisted receiver with `msg="{}"`. [3](#0-2) 

### Impact Explanation

The msg-template whitelist is the bridge's mechanism to ensure only pre-approved, well-formed messages are forwarded to whitelisted DeFi contracts via `ft_transfer_call`. Bypassing it with `{}` means the bridge will forward nBTC to a whitelisted contract with an empty-object message. The concrete harm depends on the receiver contract's `ft_on_transfer` implementation:

- If the receiver rejects `{}` (most likely for strictly-typed contracts like Burrowland), the tokens are returned and there is no fund loss.
- If any whitelisted receiver interprets `{}` as a valid default action (e.g., a simple deposit with default parameters), unintended DeFi state changes could occur.

The primary impact is **bypass of bridge policy** — the template restriction is rendered ineffective for all JSON-object templates, which is a Medium-severity policy bypass per the allowed impact scope.

### Likelihood Explanation

- Preconditions are realistic: receiver on whitelist, at least one JSON-object template registered (the test at line 485 of `unit/post_action.rs` shows exactly this configuration is expected in production).
- The depositor controls `DepositMsg` by choosing the BTC deposit address (derived from `get_deposit_path(&deposit_msg)`), so no privileged access is required.
- The bypass is deterministic and locally testable. [4](#0-3) 

### Recommendation

Change the Object branch of `is_structure_equal` to **require** that the input contains every key present in the template (i.e., treat template fields as mandatory, not optional), unless a key's template value is explicitly `null` (which already signals "unconstrained"). Alternatively, add an explicit rejection when `i_obj` is empty but `t_obj` is non-empty:

```rust
(Value::Object(t_obj), Value::Object(i_obj)) => {
    for (key, t_val) in t_obj {
        match i_obj.get(key) {
            Some(i_val) => {
                if !is_structure_equal(t_val, i_val) { return false; }
            }
            None => {
                // Only allow omission if the template value is null (unconstrained)
                if !matches!(t_val, Value::Null) { return false; }
            }
        }
    }
    for key in i_obj.keys() {
        if !t_obj.contains_key(key) { return false; }
    }
    true
}
```

### Proof of Concept

```rust
use serde_json::Value;

fn is_structure_equal(template: &Value, input: &Value) -> bool { /* as in production */ }

#[test]
fn poc_empty_object_bypasses_any_template() {
    let template: Value = serde_json::from_str(
        r#"{"Execute":{"actions":[{"IncreaseCollateral":{"token_id":"","amount":""}}]}}"#
    ).unwrap();
    let input: Value = serde_json::from_str("{}").unwrap();
    // Returns true — bypass confirmed
    assert!(is_structure_equal(&template, &input));
}
```

This matches the production template registered in the test at `unit/post_action.rs` line 485. With this bypass, `check_deposit_msg` returns `Some(post_actions)` for `msg="{}"`, and the bridge proceeds to execute `ft_transfer_call` with the empty-object message. [5](#0-4) [6](#0-5)

### Citations

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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L54-59)
```rust
impl Contract {
    pub fn check_deposit_msg(
        &self,
        deposit_msg: DepositMsg,
        actual_mintable_amount: u128,
    ) -> Option<Vec<PostAction>> {
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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L56-70)
```rust
                .get_protocol_and_relayer_fee(deposit_fee);

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

**File:** contracts/satoshi-bridge/src/unit/post_action.rs (L483-507)
```rust
    unit_env.contract.extend_post_action_msg_templates(
        burrowland_id(),
        HashSet::from([r#"{"Execute":{"actions":[{"IncreaseCollateral":{"token_id":"", "amount":"", "max_amount":""}}]}}"#.to_string()]),
    );
    assert!(unit_env
        .contract
        .check_deposit_msg(
            DepositMsg {
                recipient_id: recipient_id(),
                post_actions: Some(vec![
                    PostAction {
                        receiver_id: burrowland_id(),
                        amount: U128(10),
                        memo: None,
                        msg: "{\"Execute\":{\"actions\":[{\"IncreaseCollateral\":{\"token_id\":\"17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1\",\"max_amount\":\"1000000000000000000\"}}]}}".to_string(),
                        gas: Some(Gas::from_tgas(50))
                    },
                ]),
                extra_msg: None,
                safe_deposit: None,
                refund_address: None
            },
            100
        )
        .is_some());
```
