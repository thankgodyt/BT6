### Title
Structural-Only `msg` Template Validation in PostAction Framework Allows User-Controlled Cross-Contract Call Data — (File: `contracts/satoshi-bridge/src/deposit_msg.rs`)

### Summary
The `PostAction` framework validates user-supplied `msg` fields using `is_structure_equal`, which checks only JSON key structure (schema shape), not field values. This allows any user to pass arbitrary values inside a structurally-matching `msg` to whitelisted receiver contracts, while the bridge — a trusted caller — executes the resulting `ft_transfer_call`. This is a direct analog to the reported vulnerability class: a trusted module making cross-contract calls with user-controlled payload data.

### Finding Description

When a deposit is finalized, `check_deposit_msg` validates each `PostAction` entry. The `receiver_id` must be on an admin-controlled whitelist, and the `msg` must match an admin-set template. The template match is performed here: [1](#0-0) 

When `post_action.msg` is valid JSON, the check delegates to `is_structure_equal(&template_value, &msg_value)`. The function name and its import from `crate::json_utils` indicate it compares JSON schema shape (key presence and nesting), not field values. If a DAO-registered template is:

```json
{"action": "stake", "min_amount_out": "0"}
```

a malicious user can supply:

```json
{"action": "withdraw_all", "min_amount_out": "999999999"}
```

Both have identical structure (`action` and `min_amount_out` keys at the same nesting level), so `is_structure_equal` returns `true` and the check passes at line 136. [2](#0-1) 

The bridge then proceeds to call `ft_transfer_call` on the nBTC contract with the attacker-crafted `msg`, forwarding it to the whitelisted `receiver_id`. The bridge contract is the `predecessor_account_id` (trusted caller) in that cross-contract call chain.

The only hard guard against self-targeting is the check that `receiver_id != env::current_account_id()`: [3](#0-2) 

This prevents the bridge from calling itself, but does not prevent the bridge from calling any whitelisted contract with attacker-controlled `msg` values.

### Impact Explanation

The bridge is a privileged, trusted caller. Any whitelisted contract that interprets the `msg` field to determine how to handle received nBTC (e.g., a DEX routing instruction, a lending protocol action, a staking directive) will receive attacker-chosen values. This can cause:
- Tokens to be routed to an attacker-controlled address inside the whitelisted contract's logic.
- Unintended operations (e.g., forced liquidation, slippage bypass, wrong recipient) triggered under the bridge's authority.
- Permanent loss or locking of user nBTC if the whitelisted contract acts on the malicious `msg` irreversibly.

This matches **Medium — Harmful smart-contract behavior without direct funds theft, including broken callback rollback or stuck bridge state requiring operator intervention**, and potentially **Critical — Significant loss or theft of user funds** depending on the whitelisted contract's logic.

### Likelihood Explanation

Likelihood is **Medium-High**. Any unprivileged user submitting a BTC deposit can include a `PostAction` with a structurally-matching but value-manipulated `msg`. No special role or key is required. The attacker only needs to know the JSON key schema of a registered template (observable from on-chain state or events) and craft a deposit with a matching structure but malicious values.

### Recommendation

Replace `is_structure_equal` with exact value equality for the `msg` field. The template system should perform a full `==` comparison on the deserialized JSON value, not a structural/schema comparison. If dynamic values (e.g., amounts) must be user-supplied, define explicit allowlists of permitted keys whose values may vary, and enforce exact equality on all other keys.

### Proof of Concept

1. DAO registers a template for a whitelisted DEX contract: `{"action":"swap","recipient":"dao.near","min_out":"0"}`.
2. Attacker submits a BTC deposit with `PostAction`:
   ```json
   {
     "receiver_id": "<whitelisted-dex>",
     "amount": "1000000",
     "msg": "{\"action\":\"swap\",\"recipient\":\"attacker.near\",\"min_out\":\"0\"}"
   }
   ```
3. `check_deposit_msg` calls `is_structure_equal` on the template and the attacker's msg — both have keys `action`, `recipient`, `min_out` at the same level → returns `true`.
4. Validation passes at line 136; the bridge mints nBTC and calls `ft_transfer_call` on the nBTC contract targeting the whitelisted DEX with the attacker's `msg`.
5. The DEX's `ft_on_transfer` receives the bridge as trusted `sender_id` and routes the swap output to `attacker.near`. [4](#0-3)

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
