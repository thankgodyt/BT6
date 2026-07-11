### Title
Malicious Recipient Contract Griefs Omni Bridge Relayer via Unconstrained `ft_on_transfer` Callback in `safe_mint` - (File: contracts/nbtc/src/lib.rs)

---

### Summary

In the `safe_verify_deposit` flow, the `recipient_id` and `SafeDepositMsg.msg` are fully user-controlled. When `msg` is non-empty, `safe_mint` invokes `ft_transfer_call`, which triggers `ft_on_transfer` on the user-supplied `recipient_id` contract. A malicious recipient contract can consume all allocated gas and panic, causing the Omni Bridge relayer to lose gas on every deposit attempt. Because `safe_mint_callback` removes the UTXO key from `verified_deposit_utxo` on failure, the relayer can retry — and will lose gas again on each retry — making this a recurring, relayer-funded griefing attack.

---

### Finding Description

The deposit flow for Omni Bridge integration proceeds as follows:

1. A user embeds `recipient_id` and `safe_deposit: Some(SafeDepositMsg { msg })` in a `DepositMsg`, then sends BTC to the derived deposit address.
2. The Omni Bridge relayer calls `safe_verify_deposit`, attaching NEAR for storage and paying gas.
3. After light-client verification, `verify_safe_deposit_callback` calls `safe_mint(recipient_id, mint_amount, Some(msg))` on the nbtc contract. [1](#0-0) 

4. Inside `safe_mint`, when `msg` is `Some`, the code calls `self.ft_transfer_call(account_id, amount, None, msg)`: [2](#0-1) 

5. `ft_transfer_call` is the standard NEP-141 implementation: it transfers tokens from the bridge to `account_id`, then calls `account_id.ft_on_transfer(bridge, amount, msg)`, then `ft_resolve_transfer` as a callback.

6. There is **no validation** of `recipient_id` against any whitelist, and **no validation** of `msg` against any template. Any non-empty `msg` triggers `ft_on_transfer` on an arbitrary user-controlled contract. [3](#0-2) 

7. A malicious `recipient_id` contract implements `ft_on_transfer` to spin in a loop consuming all allocated gas, then panic. Because NEAR allocates gas per receipt, `ft_resolve_transfer` still executes with its reserved 5 Tgas and refunds tokens to the bridge. [4](#0-3) 

8. `safe_mint_callback` detects `is_refund_required() == true` (used amount = 0), burns the refunded tokens, and refunds the relayer's NEAR storage deposit — but **does not refund gas**. [5](#0-4) 

9. Critically, on failure the UTXO key is **removed** from `verified_deposit_utxo`, so the relayer can retry `safe_verify_deposit` for the same UTXO — and will lose gas again on every retry. [6](#0-5) 

The `msg` field is only processed to inject the UTXO ID; it is never validated: [7](#0-6) 

---

### Impact Explanation

The Omni Bridge relayer loses gas on every deposit attempt against a malicious recipient. Because the UTXO key is cleared on failure, the relayer can retry indefinitely, losing gas each time. The user's BTC is temporarily locked until the relayer stops retrying or the user separately calls `request_refund`. No nBTC is minted and no user funds are permanently lost, but the relayer suffers a recurring, attacker-controlled gas drain with no on-chain mechanism to prevent it.

This matches: **Medium — attacker-triggered temporary locking of bridged funds / harmful smart-contract behavior without direct funds theft.**

---

### Likelihood Explanation

The attack requires only:
1. Deploying a malicious NEAR contract with a gas-exhausting `ft_on_transfer`.
2. Constructing a `DepositMsg` with `recipient_id` pointing to that contract and `safe_deposit.msg` set to any non-empty string.
3. Sending BTC to the derived deposit address.

No privileged access, no whitelisting, and no cooperation from the relayer is needed. The `recipient_id` and `msg` are entirely user-controlled inputs embedded in the BTC deposit address derivation. The Omni Bridge relayer has no on-chain way to distinguish a malicious recipient from a legitimate one before executing. [8](#0-7) 

---

### Recommendation

1. **Validate `SafeDepositMsg.msg` against a whitelist or template** before passing it to `safe_mint`, analogous to how `check_deposit_msg` validates `post_actions` in the standard deposit flow.
2. **Adopt a pull mechanism**: instead of the relayer triggering `ft_transfer_call` on the recipient, mint tokens to the recipient's balance and let the recipient initiate the `ft_transfer_call` themselves.
3. **Add off-chain simulation**: the relayer should simulate the full receipt chain before submitting, and skip deposits where `ft_on_transfer` would exhaust gas. [9](#0-8) 

---

### Proof of Concept

```rust
// Malicious recipient contract deployed at evil.near
impl FungibleTokenReceiver for EvilContract {
    fn ft_on_transfer(
        &mut self,
        _sender_id: AccountId,
        _amount: U128,
        _msg: String,
    ) -> PromiseOrValue<U128> {
        // Spin until gas is exhausted, then panic
        let mut counter: u64 = 0;
        loop {
            counter = counter.wrapping_add(1);
            if env::used_gas() > env::prepaid_gas() - Gas::from_tgas(1) {
                env::panic_str("gas exhausted");
            }
        }
    }
}
```

**Attack steps:**
1. Deploy `evil.near` with the above `ft_on_transfer`.
2. Construct `DepositMsg { recipient_id: "evil.near", safe_deposit: Some(SafeDepositMsg { msg: "trigger" }), ... }`.
3. Send BTC to the deposit address derived from this `DepositMsg`.
4. Omni Bridge relayer calls `safe_verify_deposit` — gas is consumed by `evil.near.ft_on_transfer`, relayer loses gas.
5. `safe_mint_callback`

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L406-418)
```rust
        let msg = (!msg.is_empty())
            .then(|| inject_utxo_id_in_msg(msg, &pending_utxo_info.utxo_storage_key));

        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .safe_mint(recipient_id.clone(), mint_amount, msg)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .safe_mint_callback(recipient_id.clone(), mint_amount, pending_utxo_info),
            )
            .into()
```

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L438-455)
```rust
        } else {
            self.data_mut()
                .verified_deposit_utxo
                .remove(&pending_utxo_info.utxo_storage_key);

            ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
                .with_static_gas(GAS_FOR_BURN_CALL)
                .burn(
                    env::current_account_id(),
                    mint_amount,
                    relayer_account_id,
                    U128(0),
                )
                .detach();

            Promise::new(env::signer_account_id())
                .transfer(self.required_balance_for_safe_deposit())
                .detach();
```

**File:** contracts/nbtc/src/lib.rs (L31-32)
```rust
const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas::from_tgas(5);
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(30);
```

**File:** contracts/nbtc/src/lib.rs (L100-124)
```rust
    #[payable]
    pub fn safe_mint(
        &mut self,
        account_id: AccountId,
        amount: U128,
        msg: Option<String>,
    ) -> PromiseOrValue<U128> {
        self.assert_bridge();
        require!(
            account_id != self.bridge_id,
            "safe_mint: account_id must not be the bridge"
        );
        self.token.internal_deposit(&self.bridge_id, amount.into());

        if self.token.accounts.get(&account_id).is_none() {
            return PromiseOrValue::Value(U128(0));
        }

        if let Some(msg) = msg {
            self.ft_transfer_call(account_id, amount, None, msg)
        } else {
            self.ft_transfer(account_id, amount, None);
            PromiseOrValue::Value(amount)
        }
    }
```

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L30-47)
```rust
#[near(serializers = [json])]
#[derive(Clone)]
pub struct SafeDepositMsg {
    pub msg: String,
    // TODO: add relayer fee support in the future.
}

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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L54-116)
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
```
