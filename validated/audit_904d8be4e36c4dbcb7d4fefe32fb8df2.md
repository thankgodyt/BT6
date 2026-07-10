### Title
Insufficient Post-Action Message Validation: `is_structure_equal` Checks Structure Only, Not String Values — (File: `contracts/satoshi-bridge/src/json_utils.rs`)

### Summary

The `is_structure_equal` function used to validate `post_action.msg` against DAO-registered templates only checks that JSON value **types** match — it never compares actual string content. Any string in the template matches any string in the input. This is the direct analog of the external report's `contains()` bypass: the bridge performs a superficial structural check instead of a strict value comparison, allowing an attacker to craft a `DepositMsg` whose `post_actions.msg` passes template validation while carrying attacker-controlled string payloads.

### Finding Description

`check_deposit_msg` in `deposit_msg.rs` validates each `PostAction.msg` against the DAO-registered templates stored in `post_action_msg_templates`: [1](#0-0) 

When the message parses as JSON, validation is delegated to `is_structure_equal`. That function, for the `String` case, is: [2](#0-1) 

`(Value::String(_), Value::String(_)) => true` — the actual string content is never compared. Any string value satisfies any string template value.

Additionally, Rule 1 of the function makes every template field optional: [3](#0-2) 

If the input object omits a key present in the template, the check is silently skipped. This means an empty object `{}` matches **any** template object.

**Concrete bypass scenarios:**

Suppose the DAO registers the template:
```json
{"action": "swap", "pool_id": "legitimate-pool.near", "min_amount_out": "1000000"}
```

An attacker submits:
```json
{"action": "drain_all", "pool_id": "attacker.near", "min_amount_out": "0"}
```

`is_structure_equal` returns `true` because all values are strings and no extra keys are present. The attacker's message passes validation and is forwarded to the whitelisted receiver contract.

Alternatively, the attacker submits `{}` (empty object), which also passes because all template keys are treated as optional.

### Impact Explanation

The `post_action_msg_templates` system is the bridge's policy control for restricting what messages can be sent to whitelisted receiver contracts during the deposit flow. Bypassing it allows an attacker to send arbitrary string-valued messages to any whitelisted contract (e.g., a DEX, lending protocol, or vault). If those contracts use the `msg` field to determine routing, recipients, slippage parameters, or operation type, the attacker can trigger unintended contract behavior — including directing their deposited nBTC to unintended destinations or manipulating shared contract state. This constitutes a bypass of bridge policy with potential for harmful smart-contract behavior. [4](#0-3) 

### Likelihood Explanation

Any user who deposits BTC can craft a `DepositMsg` with arbitrary `post_actions.msg` values. The deposit address is derived from the `DepositMsg` hash, so the attacker simply deposits BTC to the address derived from their malicious message and waits for a relayer to submit the proof. No privileged access is required. The only constraint is that `receiver_id` must be on the whitelist, but the message content is fully attacker-controlled. [5](#0-4) 

### Recommendation

Replace the type-only string comparison in `is_structure_equal` with exact value comparison for `String` variants:

```rust
// Current (broken):
(Value::String(_), Value::String(_)) => true,

// Fixed:
(Value::String(t_s), Value::String(i_s)) => t_s == i_s,
```

If the intent is to allow any string value for certain fields, use `Value::Null` in the template for those fields (which is already the documented "unconstrained" sentinel per Rule 5). [6](#0-5) 

### Proof of Concept

1. DAO registers template for whitelisted DEX contract `dex.near`:
   ```json
   {"action": "swap", "token_out": "usdc.near", "min_amount_out": "1000000"}
   ```
2. Attacker constructs `DepositMsg`:
   ```json
   {
     "recipient_id": "attacker.near",
     "post_actions": [{
       "receiver_id": "dex.near",
       "amount": "100000000",
       "msg": "{\"action\": \"withdraw_all\", \"token_out\": \"attacker.near\", \"min_amount_out\": \"0\"}"
     }]
   }
   ```
3. Attacker deposits BTC to the address derived from this `DepositMsg`.
4. Relayer calls `verify_deposit_v2` with the proof.
5. `check_deposit_msg` calls `is_structure_equal(template, attacker_msg)`:
   - `"action"`: `String` vs `String` → `true`
   - `"token_out"`: `String` vs `String` → `true`
   - `"min_amount_out"`: `String` vs `String` → `true`
   - No extra keys → `true`
   - Result: **validation passes**
6. Bridge executes `ft_transfer_call` to `dex.near` with the attacker's message, forwarding the minted nBTC with attacker-controlled parameters. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L54-192)
```rust
impl Contract {
    pub fn check_deposit_msg(
        &self,
        deposit_msg: DepositMsg,
        actual_mintable_amount: u128,
    ) -> Option<Vec<PostAction>> {
        let post_actions = deposit_msg.post_actions?;
        if post_actions.is_empty() {
            Event::InvalidPostAction {
                index: None,
                err_msg: "empty post_actions.".to_string(),
            }
            .emit();
            return None;
        }
        // post_actions supports at most two.
        if post_actions.len() > MAX_POST_ACTIONS_NUM {
            Event::InvalidPostAction {
                index: None,
                err_msg: format!(
                    "The number({}) of post_actions exceeds the limit of {}.",
                    post_actions.len(),
                    MAX_POST_ACTIONS_NUM
                ),
            }
            .emit();
            return None;
        }
        let mut total_gas = 0;
        let mut total_amount = 0;
        for (index, post_action) in post_actions.iter().enumerate() {
            total_amount += post_action.amount.0;
            // The receiver_id cannot be the bridge itself — that would let a
            // deposit immediately drive the bridge's own ft_on_transfer flow
            // (e.g. TokenReceiverMessage::Withdraw) inside the relayer-paid
            // receipt, which is outside the intended deposit semantics.
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
            }
            if let Some(gas) = post_action.gas {
                // The gas specified by a single post_action must be between 30 Tgas and 100 Tgas, inclusive.
                if gas.as_gas() > MAX_PER_POST_ACTIONS_GAS.as_gas() {
                    Event::InvalidPostAction {
                        index: Some(index),
                        err_msg: format!(
                            "The amount({gas}) of gas exceeds the limit of {MAX_PER_POST_ACTIONS_GAS}."
                        ),
                    }
                    .emit();
                    return None;
                }
                if gas.as_gas() < MIN_PER_POST_ACTIONS_GAS.as_gas() {
                    Event::InvalidPostAction {
                        index: Some(index),
                        err_msg: format!(
                            "The gas amount({gas}) does not meet the minimum requirement of {MIN_PER_POST_ACTIONS_GAS}."
                        ),
                    }
                    .emit();
                    return None;
                }
                total_gas += gas.as_gas();
            }
        }
        // The total gas for all post_actions must not exceed 130 Tgas.
        if total_gas > MAX_TOTAL_POST_ACTIONS_GAS.as_gas() {
            Event::InvalidPostAction {
                index: None,
                err_msg: format!(
                    "The total amount({total_gas}) of gas exceeds the limit of {MAX_TOTAL_POST_ACTIONS_GAS}."
                ),
            }
            .emit();
            return None;
        }
        if total_amount > actual_mintable_amount {
            Event::InvalidPostAction {
                index: None,
                err_msg: format!(
                    "The total amount({total_amount}) of nBTC used in post_actions exceeds the mint amount ({actual_mintable_amount})."
                ),
            }
            .emit();
            return None;
        }
        Some(post_actions)
    }
```

**File:** contracts/satoshi-bridge/src/json_utils.rs (L1-55)
```rust
use crate::Value;

/// Recursively checks whether the structure of `input` matches the structure of `template`.
/// Values can differ, but keys and value types must conform to the `template`.
///
/// Rules:
/// 1. `input` may omit fields defined in the `template` (treated as optional).
/// 2. `input` must not contain extra fields not present in the `template`.
/// 3. If the template array has only one element, it's treated as a regular array:
///    all elements in `input` must match the type of the template element.
/// 4. If the template array has multiple elements, it's treated as an enum array:
///    all elements in `input` must match one of the enum variants.
/// 5. If a template value is `null`, then any corresponding input value is accepted (i.e., unconstrained).
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
