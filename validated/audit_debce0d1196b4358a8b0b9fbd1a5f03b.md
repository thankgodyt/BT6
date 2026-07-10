### Title
`post_action_msg_templates` Policy Bypass via Structure-Only Validation in `is_structure_equal` - (File: `contracts/satoshi-bridge/src/json_utils.rs`)

### Summary
The bridge enforces a DAO-configured `post_action_msg_templates` policy to restrict which messages a depositor may pass to whitelisted cross-contract call receivers during the deposit flow. However, the validation function `is_structure_equal` only checks that the JSON *shape* (key names and value types) of the user-supplied `msg` matches a template — it never compares actual primitive values. An unprivileged depositor can therefore supply any string or numeric content in every field of the message and still pass the template check, completely nullifying the policy's value-level restrictions.

### Finding Description
`check_deposit_msg` in `deposit_msg.rs` validates each `PostAction.msg` against the DAO-registered templates for that receiver:

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
``` [1](#0-0) 

The delegated check is `is_structure_equal` in `json_utils.rs`:

```rust
(Value::String(_), Value::String(_)) => true,
(Value::Number(_), Value::Number(_)) => true,
(Value::Bool(_),   Value::Bool(_))   => true,
(Value::Null, _)                     => true,
``` [2](#0-1) 

The function's own documentation confirms this: *"Values can differ, but keys and value types must conform to the template."* Any string in the template matches any string in the input; any number matches any number. Only the presence and type of keys is enforced.

Consequently, if the DAO registers the template:
```json
{"action":"deposit","token_id":"usdc.near","min_amount_out":1000000}
```
an attacker can supply:
```json
{"action":"withdraw_all","token_id":"attacker.near","min_amount_out":0}
```
and `is_structure_equal` returns `true` — the template check passes.

### Impact Explanation
The `post_action_msg_templates` feature exists precisely to let the DAO constrain which operations users may trigger on whitelisted receiver contracts after minting. Because value-level content is never compared, the entire value-restriction layer of this policy is inoperative. An attacker can craft a `DepositMsg` whose `post_actions[].msg` passes the structural check while encoding an entirely different operation (e.g., a different swap direction, a different target token, a zero slippage bound, or a function selector the DAO never intended to allow). The minted nBTC is then forwarded to the whitelisted contract under the attacker-chosen parameters, bypassing the DAO's intended policy.

This maps to the allowed Medium impact: **Bypass of bridge limits or policies**.

### Likelihood Explanation
The entry path is fully unprivileged: any user who deposits BTC and includes `post_actions` in their `DepositMsg` reaches `check_deposit_msg`. No special role, leaked key, or operator cooperation is required. The attacker only needs to know the structural shape of one registered template (observable from on-chain state or events) and can then freely vary all string/number values.

### Recommendation
Replace the structural-only comparison with exact value matching for primitive types. For string and number leaves the comparison should be:

```rust
(Value::String(t), Value::String(i)) => t == i,
(Value::Number(t), Value::Number(i)) => t == i,
(Value::Bool(t),   Value::Bool(i))   => t == i,
```

Reserve `Value::Null` in the template as the explicit "wildcard" sentinel for fields the DAO intentionally leaves unconstrained, and document this contract clearly. This mirrors the fix in the referenced Snaps report: render (validate) user-controlled data in a context that cannot be subverted by its content.

### Proof of Concept

1. DAO registers template for whitelisted receiver `dex.near`:
   ```json
   {"action":"swap","token_in":"nbtc.near","token_out":"usdc.near","min_out":500000}
   ```
2. Attacker deposits BTC and calls `verify_deposit_v2` with:
   ```json
   {
     "recipient_id": "attacker.near",
     "post_actions": [{
       "receiver_id": "dex.near",
       "amount": "100000000",
       "msg": "{\"action\":\"drain_liquidity\",\"token_in\":\"attacker.near\",\"token_out\":\"attacker.near\",\"min_out\":0}"
     }]
   }
   ```
3. `check_deposit_msg` calls `is_structure_equal(template, input)`.
   - Both have keys `action`, `token_in`, `token_out`, `min_out` ✓
   - `"drain_liquidity"` vs `"swap"` → both `Value::String` → `true` ✓
   - `"attacker.near"` vs `"nbtc.near"` → both `Value::String` → `true` ✓
   - `0` vs `500000` → both `Value::Number` → `true` ✓
4. `is_match = true`; the post-action is accepted and executed against `dex.near` with the attacker's chosen parameters, bypassing the DAO's intended restriction. [3](#0-2) [4](#0-3)

### Citations

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

**File:** contracts/satoshi-bridge/src/json_utils.rs (L14-55)
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
        }
        (Value::String(_), Value::String(_)) => true,
        (Value::Number(_), Value::Number(_)) => true,
        (Value::Bool(_), Value::Bool(_)) => true,
        (Value::Null, _) => true, // When a key’s value is not restricted, set its value to null.
        _ => false,
    }
```
