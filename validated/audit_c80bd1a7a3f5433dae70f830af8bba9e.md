### Title
Tokens Minted to Bridge Before Account-Registration Check in `safe_mint` Causes Permanent nBTC Supply Inflation and Irrecoverable User Fund Loss - (File: contracts/nbtc/src/lib.rs)

### Summary
`safe_mint()` in the nBTC token contract mints tokens to the bridge account **before** verifying that the recipient NEAR account is registered. If the recipient is unregistered, the function returns early with `U128(0)`, leaving the freshly minted nBTC permanently stranded in the bridge's own balance with no automated recovery path. The result is nBTC total supply inflation (more nBTC in existence than BTC backing user balances) and irrecoverable loss of the depositor's BTC.

### Finding Description
In `contracts/nbtc/src/lib.rs`, `safe_mint()` executes in this order:

1. **Line 112** — unconditionally mints `amount` tokens into `bridge_id`'s balance, increasing `ft_total_supply` by `amount`.
2. **Lines 114–116** — checks whether `account_id` is registered; if not, returns `PromiseOrValue::Value(U128(0))` immediately.
3. **Lines 118–123** — only if the account exists, transfers the minted tokens from bridge to user. [1](#0-0) 

When the early-return path (lines 114–116) is taken, the `internal_deposit` at line 112 has already permanently increased `ft_total_supply`. No subsequent burn, rollback, or `lost_found` entry is created. The minted tokens sit in the bridge's own NEP-141 balance indefinitely. [2](#0-1) 

Compare this with `mint_inner()`, which the `mint()` path uses: it calls `internal_register_account` automatically before depositing, so it never leaves tokens stranded. [3](#0-2) 

The bridge's deposit flow marks the deposit UTXO as verified in `verified_deposit_utxo` before (or as part of) calling `safe_mint`, so the user cannot subsequently request a refund on the Bitcoin side either. [4](#0-3) 

### Impact Explanation
- **nBTC supply inflation**: `ft_total_supply` grows by `amount` with no corresponding user balance, breaking the 1:1 BTC-backing invariant. The bridge holds nBTC that is not redeemable by any user.
- **User BTC permanently locked**: the deposit UTXO is marked verified, blocking any refund path. The user loses their BTC with no automated recovery.
- **No `lost_found` entry**: unlike the `transfer_nbtc_callback` failure path (which does record `lost_found`), `safe_mint`'s early return creates no recovery record, so even operator tooling has no structured way to identify affected users. [5](#0-4) 

This matches the **Medium** allowed impact: *"broken callback rollback"* and *"stuck bridge state requiring operator intervention,"* as well as supply backing below the minted amount.

### Likelihood Explanation
Any depositor whose NEAR account is not yet registered in the nBTC contract (via `storage_deposit`) at the time the relayer submits the deposit proof will trigger this path. This is a realistic scenario:

- A user derives a deposit address and sends BTC before completing NEAR-side setup.
- A user's storage registration expires or is unregistered between deposit and proof submission.
- An attacker deliberately sends BTC on behalf of an unregistered account to grief the protocol's supply accounting.

The check `self.token.accounts.get(&account_id).is_none()` is a standard NEP-141 registration check; unregistered accounts are a normal operational condition. [6](#0-5) 

### Recommendation
Reorder the logic so that minting only occurs after confirming the recipient is reachable, using one of:

1. **Check before mint**: move the `accounts.get` check to before `internal_deposit`; if unregistered, return `U128(0)` without minting.
2. **Auto-register**: call `internal_register_account` (as `mint_inner` does) before `internal_deposit`, eliminating the unregistered case entirely.
3. **Burn on early return**: if the early-return path is taken, call `internal_withdraw(&self.bridge_id, amount)` to reverse the mint and restore supply integrity, and emit a `FtBurn` event.
4. **Add to `lost_found`**: at minimum, record the stranded amount in the bridge's `lost_found` map so operators can identify and manually recover affected deposits.

### Proof of Concept
1. User derives a deposit address for NEAR account `alice.near`.
2. User sends 0.01 BTC to that address on Bitcoin.
3. `alice.near` has **not** called `storage_deposit` on the nBTC contract.
4. Relayer submits the deposit proof; bridge verifies it and marks the UTXO in `verified_deposit_utxo`.
5. Bridge calls `nbtc.safe_mint(alice.near, 1_000_000 /* satoshis */, None)`.
6. `safe_mint` executes `internal_deposit(&bridge_id, 1_000_000)` → `ft_total_supply` increases by 1,000,000.
7. `self.token.accounts.get(&alice.near)` returns `None` → function returns `U128(0)`.
8. **Result**: `ft_total_supply` is 1,000,000 higher than all user balances combined; `alice.near` holds 0 nBTC; the deposit UTXO is verified so no refund is possible; no `lost_found` entry exists. Alice's BTC is irrecoverable without manual operator intervention. [7](#0-6)

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

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L61-74)
```rust
        if !promise_success {
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
                amount,
            }
            .emit();
        }
        event.emit();
        promise_success
```
