### Title
Unchecked Token Mint Before Transfer Validation in `safe_mint` Leaves nBTC Permanently Stuck in Bridge Balance — (File: `contracts/nbtc/src/lib.rs`)

### Summary
The `safe_mint` function in the `nbtc` contract unconditionally mints tokens to `bridge_id` before verifying that the recipient account is registered. If the recipient is unregistered, the function silently returns `U128(0)` (failure) while the minted tokens remain permanently in the bridge's balance on the nbtc contract, with no recovery path in the nbtc contract itself.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint` executes `internal_deposit` to the bridge's own account before checking whether the target `account_id` is registered:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, ...);
    self.token.internal_deposit(&self.bridge_id, amount.into()); // ← tokens minted here unconditionally

    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // ← returns failure, but tokens already minted
    }
    ...
}
``` [1](#0-0) 

The `internal_deposit` call on line 112 increases both the bridge's token balance and the total supply. If the user's account is not registered (line 114), the function returns `U128(0)` — signaling failure to the bridge's callback — but the minted tokens are already credited to `bridge_id` on the nbtc contract. The nbtc contract provides no mechanism to recover or burn these orphaned tokens.

This is directly analogous to the reference report's pattern: a token operation (mint + transfer) where the transfer step fails silently while the mint step has already committed state, leaving tokens in an unrecoverable intermediate state.

### Impact Explanation
- The minted `amount` of nBTC is permanently credited to `bridge_id`'s balance on the nbtc contract, inflating total supply without a corresponding user balance.
- The bridge's callback receives `U128(0)` and is expected to "revert the whole transaction if minting fails" per the documented safe-deposit semantics, but the nbtc state change (the `internal_deposit`) cannot be undone by the bridge's callback without an explicit cross-contract `burn` call back to the nbtc contract.
- The deposit UTXO is marked as verified (preventing re-deposit), so the user's BTC is locked on-chain.
- Result: user loses BTC, nBTC supply is inflated above backed supply, and the orphaned tokens are stuck in the bridge's nbtc balance.

This matches the **Medium** impact class: permanent burning below backed supply / broken callback rollback / stuck bridge state requiring operator intervention. [2](#0-1) 

### Likelihood Explanation
Any user who sends BTC to a deposit address via the safe-deposit flow (`deposit_msg.safe_deposit = Some(..)`) without first registering their NEAR account on the nbtc contract will trigger this path. Account registration on NEP-141 tokens is a separate, non-obvious prerequisite. This is a realistic user error, especially for new users or integrations that assume the bridge handles registration. The `safe_mint` entrypoint is reachable by any relayer submitting a valid `verify_deposit_v2` proof for a safe-deposit message. [3](#0-2) 

### Recommendation
Reorder the logic in `safe_mint` to check account registration **before** minting:

```rust
pub fn safe_mint(&mut self, account_id: AccountId, amount: U128, msg: Option<String>) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "safe_mint: account_id must not be the bridge");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0));
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

This ensures no tokens are minted unless the transfer is guaranteed to succeed (for the synchronous path) or is at least initiated (for the `ft_transfer_call` path).

### Proof of Concept
1. User sends BTC to a deposit address derived from a `DepositMsg` with `safe_deposit = Some(..)`.
2. User does **not** register their NEAR account on the nbtc contract (no `storage_deposit` call).
3. Relayer submits `verify_deposit_v2` with the valid `TxInclusionProof`.
4. Bridge verifies the proof and calls `safe_mint(user_account_id, amount, None)` on the nbtc contract.
5. `safe_mint` executes `self.token.internal_deposit(&self.bridge_id, amount.into())` — `amount` nBTC is minted to the bridge's balance, total supply increases.
6. `self.token.accounts.get(&account_id).is_none()` is `true` — function returns `U128(0)`.
7. Bridge's callback receives `U128(0)` (failure). The bridge marks the deposit as failed and the UTXO as verified.
8. The `amount` nBTC remains permanently in the bridge's nbtc balance. The user's BTC is locked (UTXO verified, cannot be re-deposited). The nBTC total supply exceeds the backed supply by `amount`. [1](#0-0) [4](#0-3)

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
