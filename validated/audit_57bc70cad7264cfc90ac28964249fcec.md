### Title
Premature Mint Before Registration Check Permanently Locks nBTC in Bridge Account — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `safe_mint` function in the `nbtc` contract mints tokens to `bridge_id` **before** checking whether the recipient account is registered. If the recipient is unregistered, the function silently returns `U128(0)` without reverting the mint, leaving the newly minted nBTC permanently stranded in `bridge_id` with no recovery path. This is a direct structural analog to the reported "mint after balance check" class: a mint operation executes before a gating condition is evaluated, causing the minted tokens to be irrecoverable when that condition fails.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes as follows:

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
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← mint happens HERE

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));                   // ← registration check AFTER mint
    }
    // transfer to account_id only if registered
    ...
}
``` [1](#0-0) 

The ordering is:
1. `internal_deposit(&self.bridge_id, amount)` — increases `bridge_id`'s balance and total supply unconditionally.
2. `self.token.accounts.get(&account_id).is_none()` — only then checks if the recipient is registered.
3. If unregistered → `return PromiseOrValue::Value(U128(0))` — exits without reverting the deposit to `bridge_id`.

The minted tokens now reside in `bridge_id`. There is no `lost_found` entry created, no burn, and no refund of the minted amount. The `safe_mint` path is explicitly documented as the path that "reverts the whole transaction if minting fails (no lost & found)," but the mint itself is never reverted. [2](#0-1) 

The `mint_inner` helper used by the standard `mint` path correctly registers the account before depositing, making this flaw specific to `safe_mint`:

```rust
fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
    if self.token.accounts.get(account_id).is_none() {
        self.token.internal_register_account(account_id);  // register FIRST
    }
    self.token.internal_deposit(account_id, amount.into()); // then deposit
    ...
}
``` [3](#0-2) 

### Impact Explanation
- **nBTC total supply is inflated** by `amount` with no corresponding user balance. The tokens are credited to `bridge_id` and cannot be recovered: there is no privileged function to drain or burn arbitrary `bridge_id` balances, and the `burn` function withdraws from `bridge_id` only in the context of a verified withdrawal, not to correct a stuck mint.
- **User funds are lost.** The deposit UTXO is marked `verified_deposit_utxo` by the bridge before calling `safe_mint`. Once verified, `request_refund` is blocked for that UTXO. The user's BTC is locked in the bridge pool and their nBTC never arrives.
- The backed-supply invariant (1 nBTC = 1 sat in UTXO pool) is permanently broken for the affected amount. [4](#0-3) 

### Likelihood Explanation
The `safe_mint` / `safe_verify_deposit` path is the production path for Omni Bridge integrations. Any user whose NEAR account is not yet registered in the nBTC contract (i.e., has never called `storage_deposit`) will trigger this branch. Account registration is a separate, optional step that many new users omit. A relayer submitting a proof for such a user triggers the bug with no special privileges required — the relayer is the normal, unprivileged entry point for the deposit flow. [5](#0-4) 

### Recommendation
Move the registration check **before** the mint, mirroring the correct ordering in `mint_inner`:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

This ensures that if the recipient is unregistered, no tokens are minted and the bridge callback can safely revert the deposit state without any supply side-effect.

### Proof of Concept
1. Alice deposits 0.01 BTC to her bridge deposit address. Her NEAR account `alice.near` has never called `storage_deposit` on the nBTC contract.
2. A relayer calls `verify_deposit_v2` with `deposit_msg.safe_deposit = Some(..)`.
3. The bridge verifies the inclusion proof, marks the UTXO in `verified_deposit_utxo`, then calls `nbtc.safe_mint(alice.near, 1_000_000, None)`.
4. `safe_mint` executes `internal_deposit(&bridge_id, 1_000_000)` — total supply increases by 1,000,000 sat, all credited to `bridge_id`.
5. `self.token.accounts.get(&alice.near)` returns `None` → function returns `U128(0)`.
6. The bridge callback receives `0`; the UTXO remains in `verified_deposit_utxo`.
7. Alice calls `request_refund` → rejected: "UTXO already verified via deposit."
8. Alice's 0.01 BTC is permanently locked; 1,000,000 nBTC sat in `bridge_id` with no recovery path. Total supply exceeds backed supply by 1,000,000. [1](#0-0)

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

**File:** contracts/nbtc/src/lib.rs (L341-352)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: account_id,
            amount,
            memo: None,
        }
        .emit();
    }
```

**File:** contracts/satoshi-bridge/src/refund.rs (L534-541)
```rust
        // Double-check not finalized (could have been verified between request and callback)
        require!(
            !self
                .data()
                .verified_deposit_utxo
                .contains(&utxo_storage_key),
            "UTXO already verified via deposit"
        );
```

**File:** contracts/satoshi-bridge/src/api/bridge.rs (L73-102)
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
    }
```
