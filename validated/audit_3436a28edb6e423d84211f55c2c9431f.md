### Title
Arbitrary `msg` Forwarded to Whitelisted Post-Action Receivers When No Templates Are Configured - (File: contracts/satoshi-bridge/src/deposit_msg.rs)

---

### Summary

The `check_deposit_msg` function validates a user-supplied `PostAction.msg` against configured templates **only when** `post_action_msg_templates` has an entry for the target receiver. When a receiver is added to `post_action_receiver_id_white_list` without a corresponding entry in `post_action_msg_templates`, the template check is silently skipped and any arbitrary `msg` is accepted and forwarded to the whitelisted receiver via `ft_transfer_call`. This is the direct analog of the LSSVMPair `call()` vulnerability: a whitelist gates the target, but no method/selector-level filtering is enforced when the secondary restriction is absent.

---

### Finding Description

In `contracts/satoshi-bridge/src/deposit_msg.rs`, `check_deposit_msg` enforces two layers of restriction on `PostAction`:

1. `receiver_id` must be in `post_action_receiver_id_white_list` (lines 102–116).
2. If `post_action_msg_templates` contains an entry for that receiver, `msg` must structurally match one of the templates (lines 117–143).

The critical flaw is that layer 2 is **conditional on the existence of a template entry**:

```rust
if let Some(msg_templates) = self
    .data()
    .post_action_msg_templates
    .get(&post_action.receiver_id)
{
    // msg is validated here
}
// if no templates exist, this block is skipped entirely — any msg is accepted
``` [1](#0-0) 

The two whitelists are managed by entirely separate DAO functions — `extend_post_action_receiver_id_white_list` and `extend_post_action_msg_templates` — with no coupling between them: [2](#0-1) [3](#0-2) 

A receiver can therefore be whitelisted without any templates, leaving the `msg` field completely unrestricted. The `PostAction` struct exposes `receiver_id`, `amount`, `memo`, `msg`, and `gas` — all user-controlled fields embedded in the user-constructed `DepositMsg`: [4](#0-3) 

The `DepositMsg` is user-constructed: the user encodes it into the BTC deposit address derivation path, and the relayer submits it verbatim to `verify_deposit_v2`. The `msg` field is then forwarded to the whitelisted receiver via `ft_transfer_call` on the nBTC token contract. [5](#0-4) 

The only hard guard is that `receiver_id` cannot equal the bridge contract itself: [6](#0-5) 

No equivalent guard exists for the `msg` content when templates are absent.

---

### Impact Explanation

**Medium.** The template system is the bridge's mechanism for restricting which operations can be triggered on whitelisted receivers via post-actions. When templates are absent for a receiver, this restriction is entirely bypassed. A user can craft a `msg` that triggers any method on the whitelisted receiver's `ft_on_transfer` handler — including operations the DAO never intended to permit (e.g., initiating swaps with attacker-chosen parameters, triggering liquidations, or invoking privileged paths in DeFi protocols that accept nBTC). This constitutes a bypass of bridge policy and can result in harmful smart-contract behavior on whitelisted receivers, including stuck or manipulated state in downstream protocols that interact with the bridge's nBTC supply.

---

### Likelihood Explanation

**Medium.** The two whitelists are managed independently with no enforcement coupling. It is operationally plausible — and likely during initial integration of a new receiver — that a receiver is added to `post_action_receiver_id_white_list` before its templates are configured in `post_action_msg_templates`. During that window, any user with a pending BTC deposit can exploit the gap. The entry path is fully unprivileged: the user encodes the malicious `PostAction` into their `DepositMsg` before sending BTC, and the relayer submits it as part of normal deposit processing.

---

### Recommendation

Make template validation **mandatory** for all whitelisted receivers. Two options:

1. **Require templates at whitelist time**: In `extend_post_action_receiver_id_white_list`, require that a non-empty template set already exists in `post_action_msg_templates` for the receiver before it can be added to the receiver whitelist.
2. **Enforce template presence at validation time**: In `check_deposit_msg`, treat the absence of a template entry for a whitelisted receiver as a validation failure (return `None`) rather than silently skipping the check.

Option 2 is the minimal fix:

```rust
// Replace the `if let Some(...)` with a mandatory check:
let msg_templates = self
    .data()
    .post_action_msg_templates
    .get(&post_action.receiver_id)
    .ok_or("No msg templates configured for receiver")?;
// then validate msg against msg_templates
```

---

### Proof of Concept

1. DAO calls `extend_post_action_receiver_id_white_list(["defi.near"])` — no templates configured for `defi.near`.
2. Attacker constructs a `DepositMsg`:
   ```json
   {
     "recipient_id": "attacker.near",
     "post_actions": [{
       "receiver_id": "defi.near",
       "amount": "1000000",
       "msg": "{\"action\":\"swap\",\"min_out\":\"1\",\"pool_id\":99}"
     }]
   }
   ```
3. Attacker derives the deposit address from this `DepositMsg` and sends BTC to it.
4. Relayer calls `verify_deposit_v2(deposit_msg, tx_bytes, vout, proof)`.
5. `check_deposit_msg` runs: receiver `defi.near` is on whitelist ✓; `post_action_msg_templates.get("defi.near")` returns `None` → template block skipped → `msg` accepted as-is.
6. The bridge calls `ft_transfer_call("defi.near", 1000000, "{\"action\":\"swap\",...}")` on the nBTC token.
7. `defi.near`'s `ft_on_transfer` executes the attacker-chosen swap with attacker-chosen parameters, bypassing any intended msg restrictions. [1](#0-0)

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L37-47)
```rust
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PostAction {
    pub receiver_id: AccountId,
    pub amount: U128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<Gas>,
}
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L90-100)
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
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L117-144)
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
            }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L163-188)
```rust
    pub fn extend_post_action_receiver_id_white_list(&mut self, receiver_ids: Vec<AccountId>) {
        assert_one_yocto();
        for receiver_id in receiver_ids {
            let is_success = self
                .data_mut()
                .post_action_receiver_id_white_list
                .insert(receiver_id.clone());
            require!(
                is_success,
                format!("Already exist receiver_id: {}", receiver_id)
            );
        }
    }

    #[payable]
    #[access_control_any(roles(Role::DAO))]
    pub fn remove_post_action_receiver_id_white_list(&mut self, receiver_ids: Vec<AccountId>) {
        assert_one_yocto();
        for receiver_id in receiver_ids {
            let is_success = self
                .data_mut()
                .post_action_receiver_id_white_list
                .remove(&receiver_id);
            require!(is_success, format!("Invalid receiver_id: {}", receiver_id));
        }
    }
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L210-231)
```rust
    pub fn extend_post_action_msg_templates(
        &mut self,
        contract_id: AccountId,
        templates: HashSet<String>,
    ) {
        assert_one_yocto();
        require!(!templates.is_empty(), "empty templates.");
        if let Some(msg_templates) = self
            .data_mut()
            .post_action_msg_templates
            .get_mut(&contract_id)
        {
            for template in templates {
                let is_success = msg_templates.insert(template.clone());
                require!(is_success, format!("{:?} is exist.", template));
            }
        } else {
            self.data_mut()
                .post_action_msg_templates
                .insert(contract_id, templates);
        }
    }
```
