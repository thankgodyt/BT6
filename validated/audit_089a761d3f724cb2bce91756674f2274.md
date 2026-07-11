### Title
Zero-Value `PostAction` Amount Causes Silent Panic in `handle_post_action` — (File: `contracts/nbtc/src/lib.rs`)

### Summary
`check_deposit_msg` in `contracts/satoshi-bridge/src/deposit_msg.rs` does not validate that each `PostAction.amount > 0`. A user can embed a `PostAction` with `amount=0` in a `DepositMsg`, which passes all validation. When the deposit is verified and `handle_post_action` is executed, it calls `FungibleToken::internal_transfer` with `amount=0`, which panics in the NEAR SDK (the standard requires `amount > 0`). Because `handle_post_action` is dispatched via `.detach()`, the panic silently discards the post-action receipt without reverting the mint.

### Finding Description
`check_deposit_msg` enforces several constraints on `PostAction` entries — receiver whitelist, message template matching, gas bounds — but the only amount-level check is the aggregate:

```
if total_amount > actual_mintable_amount { return None; }
``` [1](#0-0) 

When `post_action.amount = 0`, `total_amount` stays at zero, the check passes, and the validated `post_actions` vector is returned to the caller. [2](#0-1) 

After a successful deposit verification, `mint()` calls `handle_post_actions` with `.detach()`:

```rust
if let Some(post_actions) = post_actions {
    Self::ext(env::current_account_id())
        .handle_post_actions(mint_account_id, post_actions)
        .detach();
}
``` [3](#0-2) 

`handle_post_actions` then dispatches each action with `.detach()`: [4](#0-3) 

Inside `handle_post_action`, the amount is passed directly to `internal_transfer` with no zero-check:

```rust
let amount = amount.into();   // amount == 0
self.token
    .internal_transfer(&sender_id, &receiver_id, amount, memo);
``` [5](#0-4) 

The NEAR SDK's `FungibleToken::internal_transfer` unconditionally requires `amount > 0` and panics otherwise. Because the receipt is detached, the panic is swallowed silently — the mint already succeeded and the user holds their nBTC, but the intended post-action (e.g., a DEX swap) never executes.

### Impact Explanation
This is a publicly reachable, panic-driven fault in a production bridge token path. Any user who encodes `amount: "0"` in a `PostAction` will have that action silently discarded after the BTC deposit is confirmed. The user retains their nBTC (no fund loss), but the cross-contract action they paid BTC fees to trigger is permanently dropped with no on-chain error signal. This matches the **Low** impact tier: panic-driven fault in a production bridge/token path without direct theft.

### Likelihood Explanation
Any NEAR account that constructs a `DepositMsg` with a `PostAction` can set `amount=0`. The deposit address is derived from the `DepositMsg` hash, so the user must intentionally (or accidentally) send BTC to an address derived from such a message. Accidental zero-amount entries are realistic in programmatic integrations. No privileged role is required.

### Recommendation
Add a per-entry zero-amount guard inside `check_deposit_msg`:

```diff
for (index, post_action) in post_actions.iter().enumerate() {
    total_amount += post_action.amount.0;
+   if post_action.amount.0 == 0 {
+       Event::InvalidPostAction {
+           index: Some(index),
+           err_msg: "PostAction amount must be positive.".to_string(),
+       }
+       .emit();
+       return None;
+   }
    ...
}
``` [6](#0-5) 

This mirrors the pattern already used for gas bounds validation and ensures `handle_post_action` is never called with a zero amount.

### Proof of Concept
1. Attacker/user constructs a `DepositMsg`:
   ```json
   {
     "recipient_id": "alice.near",
     "post_actions": [{"receiver_id": "dapp.near", "amount": "0", "msg": "...", "gas": "50000000000000"}]
   }
   ```
2. Sends BTC to the deposit address derived from this message.
3. Relayer calls `verify_deposit`; `check_deposit_msg` returns `Some(post_actions)` because `total_amount (0) <= actual_mintable_amount`.
4. `mint()` succeeds — nBTC is credited to `alice.near`.
5. `handle_post_actions` → `handle_post_action` is dispatched (detached).
6. `internal_transfer(..., 0, ...)` panics: *"The amount should be a positive number"*.
7. The detached receipt fails silently; the DEX swap (or other intended action) never runs.
8. Alice holds her nBTC; the post-action is permanently lost with no revert or error event.

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L83-85)
```rust
        let mut total_amount = 0;
        for (index, post_action) in post_actions.iter().enumerate() {
            total_amount += post_action.amount.0;
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L181-190)
```rust
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
```

**File:** contracts/nbtc/src/lib.rs (L143-147)
```rust
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
```

**File:** contracts/nbtc/src/lib.rs (L362-381)
```rust
    pub fn handle_post_actions(&mut self, sender_id: AccountId, post_actions: Vec<PostAction>) {
        for post_action in post_actions {
            let PostAction {
                receiver_id,
                amount,
                memo,
                msg,
                gas,
            } = post_action;
            if let Some(gas) = gas {
                Self::ext(env::current_account_id())
                    .with_static_gas(gas)
                    .handle_post_action(sender_id.clone(), receiver_id, amount, memo, msg)
                    .detach();
            } else {
                Self::ext(env::current_account_id())
                    .handle_post_action(sender_id.clone(), receiver_id, amount, memo, msg)
                    .detach();
            }
        }
```

**File:** contracts/nbtc/src/lib.rs (L401-403)
```rust
        let amount = amount.into();
        self.token
            .internal_transfer(&sender_id, &receiver_id, amount, memo);
```
