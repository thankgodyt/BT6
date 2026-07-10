### Title
Premature `internal_deposit` in `safe_mint` Inflates Total Supply When Recipient Is Unregistered - (File: `contracts/nbtc/src/lib.rs`)

### Summary
`safe_mint` in the nBTC token contract unconditionally mints tokens into the bridge's own balance **before** checking whether the intended recipient is registered. If the recipient is not registered, the function returns `U128(0)` without transferring, leaving the freshly minted tokens permanently orphaned in the bridge's balance. Total supply is inflated without a corresponding user balance, and the depositor's BTC remains locked in the bridge with no nBTC delivered.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes `internal_deposit` to `bridge_id` on line 112 before the registration guard on line 114: [1](#0-0) 

```
self.token.internal_deposit(&self.bridge_id, amount.into());  // supply already increased

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));   // tokens stranded in bridge_id
}
```

`internal_deposit` increases both `bridge_id`'s balance and the global `total_supply`. The early return on the unregistered-account path exits without transferring, so the minted tokens remain in `bridge_id`'s balance with no bookkeeping entry linking them to the depositor. The bridge's own accounting fields (`acc_collected_protocol_fee`, `cur_available_protocol_fee`, etc.) do not track these orphaned tokens. [2](#0-1) 

By contrast, the ordinary `mint` path (via `mint_inner`) auto-registers the recipient and deposits directly to them — it never has this ordering problem: [3](#0-2) 

### Impact Explanation
Every call to `safe_mint` for an unregistered recipient permanently inflates `ft_total_supply()` by `amount` without a matching user balance. The depositor's BTC UTXO is already locked in the bridge (marked in `verified_deposit_utxo` after deposit verification), so the user cannot request a refund. The orphaned nBTC in `bridge_id`'s balance is not tracked by any recovery mechanism visible in the contract, meaning the backed supply invariant (`total_supply == locked_BTC`) is broken downward for users and upward for the bridge's own balance. This matches the **Medium** impact class: permanent burning below backed supply / broken callback rollback causing stuck bridge state. [4](#0-3) 

### Likelihood Explanation
Any user who sends BTC to the bridge-derived deposit address without first calling `storage_deposit` on the nBTC contract will trigger this path. Storage registration is a separate, non-obvious prerequisite. New users, users interacting via scripts, or users whose storage registration expired are all realistic victims. The bridge relayer submits the proof and the bridge calls `safe_mint` — neither the relayer nor the bridge checks recipient registration before the cross-contract call chain completes. [5](#0-4) 

### Recommendation
Move the registration check **before** `internal_deposit`. If the recipient is not registered, return `U128(0)` immediately without minting:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Guard FIRST — no tokens minted if recipient is unregistered
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

This mirrors the analog fix in the referenced report: remove the optimization structure that caused partial updates and ensure the full, correct state transition is atomic.

### Proof of Concept
1. User registers a deposit address derived from their `DepositMsg` but does **not** call `storage_deposit` on the nBTC contract.
2. User sends BTC to that address; a relayer submits `verify_deposit` with a valid Merkle proof.
3. Bridge calls `safe_mint(user_account, amount, msg)` on the nBTC contract.
4. `internal_deposit(&bridge_id, amount)` executes — `bridge_id.balance += amount`, `total_supply += amount`.
5. `self.token.accounts.get(&user_account)` returns `None` → function returns `U128(0)`.
6. Result: `ft_total_supply()` is inflated by `amount`; `user_account` has zero nBTC; the deposit UTXO is marked verified, blocking any refund path; the `amount` tokens sit orphaned in `bridge_id`'s balance with no recovery mechanism. [1](#0-0)

### Citations

**File:** contracts/nbtc/src/lib.rs (L101-124)
```rust
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

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```

**File:** contracts/nbtc/src/lib.rs (L341-346)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
```

**File:** contracts/satoshi-bridge/src/lib.rs (L127-147)
```rust
pub struct ContractData {
    pub config: LazyOption<Config>,
    pub accounts: IterableMap<AccountId, VAccount>,
    pub utxos: IterableMap<String, VUTXO>,
    pub unavailable_utxos: IterableMap<String, VUTXO>,
    pub verified_deposit_utxo: LookupSet<String>,
    pub btc_pending_infos: IterableMap<String, VBTCPendingInfo>,
    pub rbf_txs: IterableMap<String, HashSet<String>>,
    pub relayer_white_list: IterableSet<AccountId>,
    pub extra_msg_relayer_white_list: IterableSet<AccountId>,
    pub post_action_receiver_id_white_list: IterableSet<AccountId>,
    pub post_action_msg_templates: IterableMap<AccountId, HashSet<String>>,
    pub pending_tx_limits: IterableMap<AccountId, u32>,
    pub lost_found: IterableMap<AccountId, u128>,
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
}
```
