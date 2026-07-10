### Title
Zero-value `PostAction.amount` causes silent panic in `handle_post_action`, breaking the post-mint callback - (File: contracts/nbtc/src/lib.rs)

### Summary

`check_deposit_msg` in `contracts/satoshi-bridge/src/deposit_msg.rs` validates `PostAction` entries but never asserts that each entry's `amount > 0`. A user can embed a `PostAction` with `amount: 0` inside a `DepositMsg`. After the nBTC mint succeeds, `handle_post_action` in `contracts/nbtc/src/lib.rs` calls `internal_transfer` with `amount = 0`, which panics per the NEP-141 standard. Because `handle_post_actions` is fired with `.detach()`, the panic is silent and the mint is not rolled back.

### Finding Description

`check_deposit_msg` accumulates `total_amount` across all `PostAction` entries and rejects the batch only if `total_amount > actual_mintable_amount`. It never checks whether any individual entry has `amount == 0`. [1](#0-0) 

A `PostAction` with `amount: 0` passes every validation gate (whitelist, msg-template, gas limits, total-amount ceiling) and is forwarded to the nBTC contract's `mint` call.

Inside `mint`, `handle_post_actions` is scheduled with `.detach()`: [2](#0-1) 

`handle_post_actions` then fires each `handle_post_action` also with `.detach()`: [3](#0-2) 

Inside `handle_post_action`, the zero amount is passed directly to `internal_transfer`: [4](#0-3) 

The NEAR SDK's `FungibleToken::internal_transfer` unconditionally panics when `amount == 0` ("The amount should be a positive number"). Because the call was detached, the panic is swallowed silently. The nBTC tokens are already minted to `mint_account_id` and remain there; the intended DeFi forwarding action never executes.

### Impact Explanation

The post-mint callback fails silently. The user's nBTC is minted and stays in their account, so there is no direct fund theft. However, the bridge emits a `FtMint` event and records the UTXO as verified while the intended downstream action (e.g., depositing into a DeFi protocol) never occurs. Any protocol that relies on the post_action executing atomically with the mint will be left in an inconsistent state. This is a panic-driven fault in a production bridge/token path without direct theft — matching the **Low** allowed impact.

### Likelihood Explanation

Any unprivileged NEAR account that submits a `verify_deposit` call can include a `PostAction` with `amount: 0`. No special role or leaked key is required. The `check_deposit_msg` validation path is publicly reachable via `verify_deposit` / `verify_deposit_v2`. [5](#0-4) 

### Recommendation

Add a per-entry zero-amount guard inside `check_deposit_msg`:

```rust
if post_action.amount.0 == 0 {
    Event::InvalidPostAction {
        index: Some(index),
        err_msg: "post_action amount must be greater than zero.".to_string(),
    }.emit();
    return None;
}
``` [6](#0-5) 

### Proof of Concept

1. Attacker (or any user) constructs a `DepositMsg` with `post_actions: [{ receiver_id: <whitelisted>, amount: "0", msg: <valid template>, gas: 30_000_000_000_000 }]`.
2. Submits `verify_deposit_v2` with a valid BTC transaction proof.
3. `check_deposit_msg` passes the zero-amount entry through (total_amount = 0 ≤ actual_mintable_amount).
4. `verify_deposit_callback` → `internal_mint_promise` → nBTC `mint` executes; nBTC is minted to the user.
5. `handle_post_actions` is detached; `handle_post_action` is called with `amount = 0`.
6. `internal_transfer` panics — the post_action never executes, but the mint is already final. [7](#0-6) [8](#0-7)

### Citations

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L55-90)
```rust
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
```

**File:** contracts/nbtc/src/lib.rs (L143-147)
```rust
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
```

**File:** contracts/nbtc/src/lib.rs (L371-380)
```rust
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
```

**File:** contracts/nbtc/src/lib.rs (L384-416)
```rust
    #[private]
    pub fn handle_post_action(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) {
        require!(
            env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL,
            "More gas is required"
        );
        require!(
            receiver_id != self.bridge_id,
            "handle_post_action: receiver_id must not be the bridge"
        );
        let amount = amount.into();
        self.token
            .internal_transfer(&sender_id, &receiver_id, amount, memo);
        let receiver_gas = env::prepaid_gas()
            .checked_sub(GAS_FOR_FT_TRANSFER_CALL)
            .unwrap_or_else(|| env::panic_str("Prepaid gas overflow"));
        // Initiating receiver's call and the callback
        ext_ft_receiver::ext(receiver_id.clone())
            .with_static_gas(receiver_gas)
            .ft_on_transfer(sender_id.clone(), amount.into(), msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .ft_resolve_transfer(sender_id, receiver_id, amount.into()),
            )
            .detach();
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L73-101)
```rust
    pub fn verify_deposit_v2(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Base64VecU8,
        vout: usize,
        proof: TxInclusionProof,
    ) -> Promise {
        let coinbase_proof = Some((proof.coinbase_tx_id, proof.coinbase_merkle_proof));
        if deposit_msg.safe_deposit.is_some() {
            self.internal_safe_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        } else {
            self.internal_verify_deposit_entry(
                deposit_msg,
                tx_bytes.0,
                vout,
                proof.tx_block_blockhash,
                proof.tx_index,
                proof.merkle_proof,
                coinbase_proof,
            )
        }
```
