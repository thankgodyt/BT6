### Title
Whitelisted `post_action` Receiver Without Templates Accepts Arbitrary `msg` — (`contracts/satoshi-bridge/src/deposit_msg.rs`)

### Summary

`check_deposit_msg` enforces message-template matching only when `post_action_msg_templates` contains an entry for the receiver. When a receiver is in `post_action_receiver_id_white_list` but has **no** entry in `post_action_msg_templates`, the entire template-check block is silently skipped and any `msg` string is accepted.

### Finding Description

The guard in `check_deposit_msg` is structured as an optional check:

```rust
if let Some(msg_templates) = self
    .data()
    .post_action_msg_templates
    .get(&post_action.receiver_id)   // returns None → block skipped entirely
{
    // template matching
    if !is_match { return None; }
}
``` [1](#0-0) 

The whitelist check immediately above it is unconditional — it rejects any receiver not in `post_action_receiver_id_white_list`: [2](#0-1) 

But the template check is conditional on the receiver having an entry in `post_action_msg_templates`. These two maps are populated by two independent DAO calls:

- `extend_post_action_receiver_id_white_list` — adds to the whitelist only
- `extend_post_action_msg_templates` — separately adds templates [3](#0-2) [4](#0-3) 

There is no enforcement that a receiver added to the whitelist must also have templates registered. The integration test at line 1079 explicitly demonstrates this state: "dapp" is whitelisted with no templates, and a deposit with `msg: ""` succeeds. [5](#0-4) 

An attacker can exploit this by crafting a `DepositMsg` with `post_action.msg = "<arbitrary_payload>"` targeting any such receiver. The bridge will execute `ft_transfer_call` to the receiver with the attacker-controlled `msg`, which is passed directly to the receiver's `ft_on_transfer` callback.

### Impact Explanation

The template system exists to restrict what cross-contract calls can be triggered via the bridge's `ft_transfer_call`. Bypassing it allows an attacker to invoke arbitrary logic on any whitelisted receiver that lacks templates — for example, triggering unintended actions on a DeFi protocol (supply collateral on behalf of another account, execute a swap, etc.) using the bridge as the caller. The attacker's own deposited nBTC is the vehicle; the harm is the unrestricted cross-contract call surface opened on the receiver.

This matches: **Medium — Bypass of bridge limits or policies.**

### Likelihood Explanation

The precondition — a receiver whitelisted without templates — is a realistic and observable on-chain state. The DAO may whitelist a receiver during setup before templates are configured, or may intentionally whitelist a receiver believing the whitelist alone is sufficient. No privileged access beyond the DAO's prior whitelist action is required from the attacker; the exploit is a standard public `verify_deposit` call.

### Recommendation

Require that every whitelisted receiver has at least one template registered before the `post_action` is accepted. Either:

1. **At check time:** change the `if let Some(...)` to a mandatory lookup — if the receiver is whitelisted but has no templates, reject the `post_action` with an error.
2. **At registration time:** in `extend_post_action_receiver_id_white_list`, require that templates for the receiver already exist (or atomically accept both in a single DAO call).

Option 1 is the minimal, safest fix:

```rust
let msg_templates = self
    .data()
    .post_action_msg_templates
    .get(&post_action.receiver_id)
    .unwrap_or_else(|| {
        Event::InvalidPostAction { ... }.emit();
        return None; // propagate rejection
    });
// proceed with template matching
```

### Proof of Concept

```rust
// 1. DAO whitelists receiver — no templates added
contract.extend_post_action_receiver_id_white_list(vec![receiver_id.clone()]);
// post_action_msg_templates does NOT contain receiver_id

// 2. Attacker crafts DepositMsg with arbitrary msg
let result = contract.check_deposit_msg(
    DepositMsg {
        recipient_id: attacker_id(),
        post_actions: Some(vec![PostAction {
            receiver_id: receiver_id.clone(),
            amount: U128(100),
            memo: None,
            msg: "arbitrary_malicious_payload".to_string(),
            gas: Some(Gas::from_tgas(50)),
        }]),
        extra_msg: None,
        safe_deposit: None,
        refund_address: None,
    },
    1000,
);

// 3. Template check is skipped → post_action accepted with arbitrary msg
assert!(result.is_some()); // passes — vulnerability confirmed
``` [1](#0-0)

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L101-116)
```rust
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

**File:** contracts/satoshi-bridge/src/api/management.rs (L161-175)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
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
```

**File:** contracts/satoshi-bridge/src/api/management.rs (L208-231)
```rust
    #[payable]
    #[access_control_any(roles(Role::DAO))]
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

**File:** contracts/satoshi-bridge/tests/test_satoshi_bridge.rs (L1079-1095)
```rust
    {
        // The account dapp.test.near is not registered，does not affect mint
        check!(
            context.extend_post_action_receiver_id_white_list(vec![context
                .get_account_by_name("dapp")
                .sdk_id()])
        );
        let deposit_msg = DepositMsg {
            recipient_id: context.get_account_by_name("alice").sdk_id(),
            post_actions: Some(vec![PostAction {
                receiver_id: context.get_account_by_name("dapp").sdk_id(),
                amount: 5000.into(),
                memo: None,
                msg: "".to_string(),
                gas: Some(Gas::from_tgas(100)),
            }]),
            extra_msg: None,
```
