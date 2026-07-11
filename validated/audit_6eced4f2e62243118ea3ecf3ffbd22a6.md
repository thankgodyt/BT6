### Title
Premature Mint Before Registration Check Permanently Locks Tokens at Bridge in `safe_mint` - (File: contracts/nbtc/src/lib.rs)

### Summary
The `safe_mint` function in the nbtc token contract mints tokens to the bridge's own account (`bridge_id`) **before** checking whether the recipient account is registered. When the recipient is unregistered, the function returns `U128(0)` without transferring, leaving the minted tokens permanently stuck at `bridge_id` with no recovery path for the user.

### Finding Description
In `contracts/nbtc/src/lib.rs`, the `safe_mint` function executes a state-mutating mint before its guard check:

```rust
pub fn safe_mint(&mut self, account_id: AccountId, amount: U128, msg: Option<String>) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← mints first
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← returns 0, tokens stuck
    }
    // transfer only reached if account is registered
    ...
}
``` [1](#0-0) 

The call to `self.token.internal_deposit(&self.bridge_id, amount.into())` unconditionally increases the bridge's nBTC balance by `amount`. The subsequent registration check `self.token.accounts.get(&account_id).is_none()` is evaluated **after** the mint. When the recipient is unregistered, the function returns `U128(0)` and exits — the minted tokens remain at `bridge_id` with no attribution to the depositing user and no mechanism to recover them.

This is the direct analog of the `_getFirstSample` bug: under a specific condition (account not registered, analogous to buffer not full), the function returns a wrong/incomplete result (`U128(0)` instead of `amount`), producing a silent accounting failure — minted supply that is unattributed and irrecoverable.

The bridge's safe-deposit path calls `safe_mint` after light-client proof verification: [2](#0-1) 

Once the proof is accepted and `safe_mint` is called, the BTC-side UTXO is consumed. If `safe_mint` silently returns 0, the bridge has no rollback path for the BTC, and the inflated nBTC balance at `bridge_id` is untracked by any of the protocol-fee accumulators (`acc_collected_protocol_fee`, `cur_available_protocol_fee`, etc.): [3](#0-2) 

### Impact Explanation
- The nBTC total supply increases by `amount` but the user receives zero tokens.
- The bridge's nBTC balance is silently inflated; no existing accounting field tracks these orphaned tokens.
- The user's BTC is locked in the bridge's Bitcoin address with no corresponding nBTC and no refund path (the UTXO is already marked verified).
- This is a **Medium** supply/accounting failure: permanent burning below backed supply and stuck bridge state requiring operator intervention, matching the allowed impact class.

### Likelihood Explanation
Any user who initiates a safe deposit without first calling `storage_deposit` on the nBTC contract to register their NEAR account triggers this path. New users unfamiliar with NEP-141 storage registration — a common onboarding gap — will hit this silently. No privileged access is required; the entry point is the public safe-deposit BTC flow.

### Recommendation
Move the registration check **before** the mint so that no tokens are created when the recipient is unregistered:

```rust
pub fn safe_mint(&mut self, account_id: AccountId, amount: U128, msg: Option<String>) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "safe_mint: account_id must not be the bridge");
    // Guard BEFORE mint
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }
    self.token.internal_deposit(&self.bridge_id, amount.into());
    if let Some(msg) = msg {
        self.ft_transfer_call(account_id, amount, None, msg)
    } else {
        self.ft_transfer(account_id, amount, None);
        PromiseOrValue::Value(amount)
    }
}
```

### Proof of Concept
1. User deposits BTC to a safe-deposit address without registering their NEAR account on the nBTC contract.
2. Relayer submits `TxInclusionProof`; bridge verifies via light client and calls `verify_safe_deposit_callback`.
3. Callback calls `safe_mint(user_account, deposit_amount, msg)`.
4. `safe_mint` executes `internal_deposit(&bridge_id, deposit_amount)` — bridge's nBTC balance increases by `deposit_amount`.
5. `safe_mint` checks `accounts.get(&user_account)` → `None` (unregistered).
6. Returns `U128(0)` — no transfer occurs.
7. `deposit_amount` nBTC tokens are permanently stuck at `bridge_id`; user holds zero nBTC; BTC UTXO is consumed and marked verified, blocking any refund path.
8. Protocol's nBTC supply is inflated by `deposit_amount` with no corresponding user balance.

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

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L74-114)
```rust
    pub(crate) fn internal_safe_verify_deposit(
        &mut self,
        deposit_amount: u128,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
        coinbase_proof: Option<(String, Vec<String>)>,
        pending_utxo_info: PendingUTXOInfo,
        recipient_id: AccountId,
        deposit_msg: SafeDepositMsg,
    ) -> Promise {
        let config = self.internal_config();
        let confirmations = self.get_confirmations(config, deposit_amount);
        let promise = self.verify_transaction_inclusion_promise(
            config.btc_light_client_account_id.clone(),
            pending_utxo_info.tx_id.clone(),
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            coinbase_proof,
            confirmations,
        );

        if deposit_amount < config.min_deposit_amount {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_UNAVAILABLE_UTXO_CALL_BACK)
                    .unavailable_utxo_callback(recipient_id, pending_utxo_info),
            )
        } else {
            promise.then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_VERIFY_DEPOSIT_CALL_BACK)
                    .verify_safe_deposit_callback(
                        recipient_id,
                        deposit_amount.into(),
                        deposit_msg.msg,
                        pending_utxo_info,
                    ),
            )
        }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L141-146)
```rust
    pub acc_collected_protocol_fee: u128,
    pub cur_available_protocol_fee: u128,
    pub acc_claimed_protocol_fee: u128,
    pub cur_reserved_protocol_fee: u128,
    pub acc_protocol_fee_for_gas: u128,
    pub refund_requests: IterableMap<String, VRefundRequest>,
```
