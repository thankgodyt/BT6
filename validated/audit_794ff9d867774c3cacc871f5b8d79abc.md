### Title
`safe_mint` Mints to `bridge_id` Without Recovery When Recipient Is Unregistered, Breaking Backed-Supply Invariant — (`contracts/nbtc/src/lib.rs`)

### Summary

The `nbtc` contract exposes two minting paths: `mint()` (standard deposit) and `safe_mint()` (safe/Omni-Bridge deposit). The `mint()` path relies on the bridge's `lost_found` mechanism to recover tokens when a transfer to the recipient fails. The `safe_mint()` path, however, silently mints tokens to `bridge_id` and returns `U128(0)` when the recipient account is unregistered — with no recovery path. This breaks the invariant that every minted nBTC is either held by a user or recoverable via `claim_lost_found`, and permanently locks the corresponding BTC in the bridge's Bitcoin address.

### Finding Description

`safe_mint` in `contracts/nbtc/src/lib.rs` unconditionally calls `internal_deposit` to credit `bridge_id` before checking whether the intended recipient is registered:

```rust
// contracts/nbtc/src/lib.rs  lines 112-115
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));   // tokens already minted, never transferred
}
``` [1](#0-0) 

When the recipient is unregistered the function returns `U128(0)` — the NEP-141 "unused amount" sentinel — without reverting, without creating a `lost_found` entry, and without any other recovery hook. The total supply has already increased; the tokens sit at `bridge_id` permanently.

By contrast, the standard `mint()` path never deposits to `bridge_id` first; the bridge's own callback handles failures by writing to `lost_found`, from which users can recover via `claim_lost_found`. [2](#0-1) 

The `safe_mint` path is reached through `safe_verify_deposit` / `verify_deposit_v2` (when `deposit_msg.safe_deposit` is `Some`): [3](#0-2) [4](#0-3) 

The documentation for the safe path explicitly states it should **revert** on failed cross-contract calls — but the unregistered-account branch silently succeeds from the bridge's perspective (the callback sees `U128(0)` and no panic), so no revert occurs and the deposit UTXO is marked verified, permanently blocking a later refund.

### Impact Explanation

- The corresponding BTC UTXO is recorded in `verified_deposit_utxo`, preventing any future `verify_deposit` or `request_refund` from reclaiming it.
- The minted nBTC tokens accumulate at `bridge_id` with no on-chain mechanism to credit them to the intended recipient.
- Total nBTC supply exceeds the amount claimable by users — a permanent backed-supply invariant violation.
- Matches **Medium** impact: *broken callback rollback* and *permanent burning below backed supply* (nBTC minted but not deliverable).

### Likelihood Explanation

The safe-deposit path is the standard path for Omni Bridge integration. Any deposit whose recipient NEAR account has not yet called `storage_deposit` on the nBTC contract triggers this branch. A user who sends BTC before registering their NEAR account in the nBTC contract, combined with a relayer submitting the proof via the safe path, is a realistic operational scenario. No malicious actor is required; ordinary user sequencing error is sufficient.

### Recommendation

Move the registration check **before** `internal_deposit`, or revert (panic) when the recipient is unregistered instead of returning `U128(0)`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");
    // Check registration BEFORE minting
    require!(
        self.token.accounts.get(&account_id).is_some(),
        "safe_mint: recipient account not registered"
    );
    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... transfer logic
}
```

This preserves the "revert on failure" guarantee documented for the safe-deposit path and prevents supply inflation without a corresponding user claim.

### Proof of Concept

1. User sends 0.01 BTC to a deposit address derived from NEAR account `alice.near`.
2. `alice.near` has **not** called `storage_deposit` on the nBTC contract.
3. A trusted relayer calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(...)`.
4. The bridge verifies the BTC inclusion proof and calls `safe_mint(alice.near, 1_000_000, ...)` on the nBTC contract.
5. `safe_mint` executes `internal_deposit(&bridge_id, 1_000_000)` — total supply increases by 1,000,000 satoshis.
6. `self.token.accounts.get(&alice.near)` returns `None` → function returns `U128(0)`.
7. The bridge callback sees no panic and records the UTXO in `verified_deposit_utxo`.
8. Alice's BTC is permanently locked; 1,000,000 nBTC sit at `bridge_id` with no recovery path; `claim_lost_found` has no entry for Alice. [5](#0-4) [3](#0-2)

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

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L70-102)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
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
    }
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L123-145)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    #[deprecated(note = "use verify_deposit_v2 with deposit_msg.safe_deposit = Some(..)")]
    pub fn safe_verify_deposit(
        &mut self,
        deposit_msg: DepositMsg,
        tx_bytes: Vec<u8>,
        vout: usize,
        tx_block_blockhash: String,
        tx_index: u64,
        merkle_proof: Vec<String>,
    ) -> Promise {
        self.internal_safe_verify_deposit_entry(
            deposit_msg,
            tx_bytes,
            vout,
            tx_block_blockhash,
            tx_index,
            merkle_proof,
            None,
        )
    }
```
