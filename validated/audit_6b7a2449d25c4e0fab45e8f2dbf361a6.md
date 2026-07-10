### Title
Silent Token Stranding on Unregistered Recipient in `safe_mint` — (File: `contracts/nbtc/src/lib.rs`)

### Summary

The `safe_mint` function in the nBTC token contract unconditionally mints tokens to the bridge's own account before checking whether the intended recipient is registered. If the recipient is not registered, the function returns `U128(0)` without transferring the tokens, leaving them permanently stranded in the bridge's balance while the user's deposited BTC remains locked with no trustless recovery path.

### Finding Description

In `contracts/nbtc/src/lib.rs`, `safe_mint` executes in this order:

1. `self.token.internal_deposit(&self.bridge_id, amount.into())` — unconditionally increases `bridge_id`'s token balance and the global total supply by `amount`.
2. `if self.token.accounts.get(&account_id).is_none() { return PromiseOrValue::Value(U128(0)); }` — if the recipient has no storage registration, the function returns early.
3. The minted tokens remain in `bridge_id`'s balance. No transfer to the user occurs. No rollback of the mint occurs. [1](#0-0) 

The early-return branch at line 114–116 is the vulnerable path. It is the analog of the untested branch problem described in the external report: a code path that silently produces a harmful state instead of reverting or recovering. [2](#0-1) 

### Impact Explanation

- The user's BTC deposit is sent to a bridge-controlled address derived from their `DepositMsg`. Once the bridge's deposit verification succeeds, the UTXO is recorded in `verified_deposit_utxo`, permanently blocking any refund path for that UTXO. [3](#0-2) 

- The nBTC contract mints `amount` tokens to `bridge_id` (inflating total supply and bridge balance) but transfers nothing to the user.
- The bridge's callback receives `U128(0)` from `safe_mint`. The bridge's nBTC balance now contains orphaned tokens backed by the user's real BTC, but the user holds zero nBTC and has no trustless on-chain mechanism to claim them.
- The user's BTC is effectively permanently locked: the deposit UTXO is verified (no refund), and no nBTC was delivered.

**Impact class:** Critical — significant permanent locking of user funds.

### Likelihood Explanation

Any user who deposits BTC to a bridge address without first calling `storage_deposit` on the nBTC contract to register their NEAR account triggers this path. This is a realistic and common mistake: the deposit address is derived purely from the `DepositMsg` (which contains only the NEAR `recipient_id`), and nothing in the deposit flow enforces prior registration. A new user, a user bridging to a freshly created NEAR account, or a user whose storage registration has lapsed all hit this branch. [4](#0-3) 

### Recommendation

Reverse the order of operations: check whether `account_id` is registered **before** minting. If the account is not registered, either revert the entire call (so the bridge callback can handle the failure and avoid marking the UTXO as verified), or auto-register the account and proceed with the transfer. A minimal fix:

```rust
pub fn safe_mint(...) -> PromiseOrValue<U128> {
    self.assert_bridge();
    require!(account_id != self.bridge_id, "...");

    // Check registration BEFORE minting
    if self.token.accounts.get(&account_id).is_none() {
        return PromiseOrValue::Value(U128(0)); // no mint, bridge can handle
    }

    self.token.internal_deposit(&self.bridge_id, amount.into());
    // ... proceed with transfer
}
```

This ensures that if the recipient is unregistered, no tokens are minted and the bridge callback receives a clean signal to avoid finalizing the deposit.

### Proof of Concept

1. Alice creates a NEAR account `alice.near` but does **not** call `storage_deposit` on the nBTC contract.
2. Alice sends 0.01 BTC to the bridge deposit address derived from `DepositMsg { recipient_id: "alice.near", ... }`.
3. A relayer submits the transaction and Merkle proof to the bridge via `verify_deposit_v2`.
4. The bridge verifies the proof, calls `safe_mint("alice.near", 1_000_000, None)` on the nBTC contract.
5. Inside `safe_mint`: `internal_deposit(&bridge_id, 1_000_000)` executes — bridge's nBTC balance increases by 1,000,000 satoshis worth of nBTC, total supply increases.
6. `self.token.accounts.get(&"alice.near")` returns `None` → function returns `U128(0)`.
7. The bridge callback receives `U128(0)`, marks the deposit UTXO in `verified_deposit_utxo`.
8. Alice's BTC is locked. Alice holds 0 nBTC. The bridge holds 1,000,000 extra nBTC with no owner. Alice cannot request a refund (UTXO is verified). Alice cannot re-submit the deposit (UTXO already verified). Alice's funds are permanently lost without operator intervention. [5](#0-4) [6](#0-5)

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

**File:** contracts/satoshi-bridge/src/refund.rs (L253-258)
```rust
        // after a consensus branch change.
        require!(
            !self.data().verified_deposit_utxo.contains(utxo_storage_key)
                || refund_request.executed,
            "UTXO already verified via deposit, cannot refund"
        );
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

**File:** contracts/satoshi-bridge/src/deposit_msg.rs (L49-52)
```rust
pub fn get_deposit_path(deposit_msg: &DepositMsg) -> String {
    let deposit_msg_string = serde_json::to_string(&deposit_msg).unwrap();
    hex::encode(env::sha256(deposit_msg_string.as_bytes()))
}
```
