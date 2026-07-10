### Title
Unregistered-Account `safe_mint` Permanently Strands nBTC in Bridge — No Recovery Path Implemented - (File: contracts/nbtc/src/lib.rs)

### Summary
`safe_mint` in the nBTC token contract mints tokens into the bridge's own account first, then silently returns `U128(0)` if the recipient is not registered — without creating a `lost_found` entry or any other recovery record. The tokens are permanently stranded in the bridge's balance with no implemented path to retrieve them.

### Finding Description
`safe_mint` follows a two-step pattern: it calls `internal_deposit` to credit `bridge_id`, then attempts to forward the tokens to the user. [1](#0-0) 

```rust
self.token.internal_deposit(&self.bridge_id, amount.into());

if self.token.accounts.get(&account_id).is_none() {
    return PromiseOrValue::Value(U128(0));
}
```

When the recipient account has no storage registration, execution returns immediately after the deposit to `bridge_id`. The tokens now exist in the bridge's balance but are never forwarded, and no `lost_found` entry is written. Compare this with the failure path in `transfer_nbtc_callback`, which *does* write a `lost_found` record: [2](#0-1) 

The `lost_found` map is the only implemented recovery mechanism in the bridge, yet `safe_mint`'s unregistered-account branch bypasses it entirely. The `mint` function avoids this problem by calling `mint_inner`, which auto-registers the account before depositing: [3](#0-2) 

`safe_mint` provides no equivalent guarantee, leaving the recovery path unimplemented.

### Impact Explanation
Any deposit processed via `safe_mint` where the recipient has not called `storage_deposit` on the nBTC contract results in the corresponding nBTC being minted into the bridge's account and permanently inaccessible to the user. The bridge's `acc_collected_protocol_fee` / supply accounting does not reflect this stranded balance, creating a backed-supply shortfall. This matches the allowed Medium impact: *permanent burning below backed supply* and *stuck bridge state requiring operator intervention*. [4](#0-3) 

### Likelihood Explanation
NEAR NEP-141 requires explicit `storage_deposit` before a token account can receive funds. New users who deposit BTC before registering their nBTC account — a common ordering mistake — will trigger this path. No on-chain guard in `safe_mint` prevents the call from proceeding when the account is absent, and no off-chain documentation or pre-check is enforced at the bridge layer visible in the production code.

### Recommendation
Replace the early-return with one of the following:
1. **Auto-register**: call `internal_register_account` before `internal_deposit`, matching the behavior of `mint_inner`.
2. **Lost-found fallback**: write a `lost_found` entry for `account_id` so the user can later claim their tokens after registering.
3. **Revert**: `require!` that the account is registered before minting, forcing the caller to ensure registration first.

### Proof of Concept
1. User Alice sends BTC to her deposit address without first calling `storage_deposit` on the nBTC contract.
2. A relayer submits the deposit proof; the bridge calls `safe_mint(alice.near, 100_000, None)`.
3. `internal_deposit(&bridge_id, 100_000)` succeeds — bridge balance increases by 100 000 satoshis of nBTC.
4. `self.token.accounts.get(&alice.near)` returns `None`; the function returns `U128(0)`.
5. Alice's 100 000 nBTC are now in the bridge's account. No `lost_found` entry exists. Alice has no on-chain mechanism to recover them. [1](#0-0)

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

**File:** contracts/nbtc/src/lib.rs (L341-346)
```rust
    fn mint_inner(&mut self, account_id: &AccountId, amount: U128) {
        if self.token.accounts.get(account_id).is_none() {
            self.token.internal_register_account(account_id);
        }
        self.token.internal_deposit(account_id, amount.into());
        near_contract_standards::fungible_token::events::FtMint {
```

**File:** contracts/satoshi-bridge/src/token_transfer.rs (L62-68)
```rust
            self.data_mut()
                .lost_found
                .entry(account_id.clone())
                .and_modify(|v| *v += amount.0)
                .or_insert(amount.0);
            Event::LostFoundNbtc {
                account_id: &account_id,
```
