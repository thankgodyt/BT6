### Title
Whitelisted `post_action` Receivers Without Message Templates Allow Arbitrary Cross-Contract Calls as Bridge Identity — (File: `contracts/satoshi-bridge/src/deposit_msg.rs`)

---

### Summary

The `post_actions` mechanism in `DepositMsg` allows any depositing user to make the bridge contract call `ft_transfer_call` on a DAO-whitelisted receiver contract with fully user-controlled `msg` content, whenever no `post_action_msg_templates` have been registered for that receiver. The bridge contract is `predecessor_account_id` (i.e., `msg.sender`) for those cross-contract calls. This is a direct analog of the `safeFunctionCall` risk: the bridge's privileged on-chain identity is exposed to arbitrary caller-supplied payloads targeting approved external contracts.

---

### Finding Description

`check_deposit_msg` enforces two independent guards on each `PostAction`:

1. **Receiver whitelist** — `receiver_id` must be in `post_action_receiver_id_white_list`.
2. **Message template** — if `post_action_msg_templates` contains an entry for `receiver_id`, the supplied `msg` must structurally match one of those templates.

The template guard is conditional:

```rust
// contracts/satoshi-bridge/src/deposit_msg.rs  lines 117-143
if let Some(msg_templates) = self
    .data()
    .post_action_msg_templates
    .get(&post_action