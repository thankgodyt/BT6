### Title
Silent nBTC Token Lock via Unconfigured `withdraw_relayer` in Legacy `ft_transfer` Path — (File: contracts/nbtc/src/lib.rs)

---

### Summary

The `ft_transfer` function in the nBTC token contract contains a special-case branch for a legacy Near Intents withdrawal flow. When `receiver_id == env::current_account_id()` and the memo starts with `"WITHDRAW_TO:"`, the code is supposed to redirect the transfer to a configured `withdraw_relayer`. However, if `withdraw_relayer` is not set (the default state), the code silently falls through and executes `self.token.ft_transfer(receiver_id, amount, memo)` — transferring nBTC to the nBTC contract itself. The nBTC contract has no mechanism to recover tokens held by itself, making the loss permanent.

---

### Finding Description

In `contracts/nbtc/src/lib.rs`, the overridden `ft_transfer` function reads:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    // Legacy bridging flow used by Near Intents
    if receiver_id == env::current_account_id()
        && memo
            .as_ref()
            .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
    }

    self.token.ft_transfer(receiver_id, amount, memo);
}
``` [1](#0-0) 

The outer `if` block matches when the caller explicitly targets the nBTC contract itself with the `WITHDRAW_TO:` memo prefix. The inner `if let Some(...)` only redirects when a relayer is configured. When `withdraw_relayer` is `None`, control falls through to the unconditional `self.token.ft_transfer(receiver_id, amount, memo)` call at line 195, where `receiver_id` is still `env::current_account_id()` — the nBTC contract itself. [2](#0-1) 

The `withdraw_relayer` is not set during contract initialization: [3](#0-2) 

It is only set via `set_withdraw_relayer_address`, which requires the controller role: [4](#0-3) 

The nBTC contract has no function to recover tokens held by itself. The `burn` function withdraws exclusively from `self.bridge_id`: [5](#0-4) 

There is no admin sweep, rescue, or recovery path for tokens credited to `env::current_account_id()`.

For the transfer to succeed, the nBTC contract itself must be registered as a token holder. The `storage_deposit` function is publicly callable with no access control: [6](#0-5) 

An attacker can register the nBTC contract as a token holder by calling `storage_deposit(account_id = Some(nbtc_contract_id))` for a small NEAR deposit, enabling the stuck-token path for any subsequent victim.

---

### Impact Explanation

Any nBTC tokens transferred to the nBTC contract itself via this path are permanently irrecoverable. The `burn` function cannot reach them (it only burns from `bridge_id`), and no other privileged recovery path exists. This constitutes permanent destruction of user-held nBTC, which is backed 1:1 by BTC held in the bridge — the circulating supply of nBTC decreases below the backed BTC supply without any corresponding BTC release.

**Impact: Medium** — permanent burning below backed supply / permanent locking of user funds without direct theft by an attacker.

---

### Likelihood Explanation

- The `withdraw_relayer` is `None` by default; any deployment that has not explicitly called `set_withdraw_relayer_address` is vulnerable.
- The `WITHDRAW_TO:` memo prefix is a documented constant in the source (`WITHDRAW_MEMO_PREFIX = "WITHDRAW_TO:"`), making it discoverable.
- Registering the nBTC contract as a token holder via `storage_deposit` costs only a small NEAR storage deposit and is permissionless.
- A user following legacy Near Intents documentation or a dApp that constructs the `WITHDRAW_TO:` memo and targets the nBTC contract address will silently lose funds with no on-chain error.

**Likelihood: Medium** — realistic for any deployment without the relayer configured, and the silent fallthrough provides no warning to the caller.

---

### Recommendation

Replace the silent fallthrough with an explicit revert when `withdraw_relayer` is not configured:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        let relayer = Self::read_withdraw_relayer_address()
            .unwrap_or_else(|| env::panic_str("ERR_WITHDRAW_RELAYER_NOT_CONFIGURED"));
        return self.token.ft_transfer(relayer, amount, memo);
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

Alternatively, add a blanket guard at the top of `ft_transfer` that rejects any transfer where `receiver_id == env::current_account_id()`.

---

### Proof of Concept

1. **Setup**: `withdraw_relayer` is not configured (default deployment state).
2. **Attacker registers nBTC contract as token holder**: calls `storage_deposit(account_id = Some("<nbtc_contract_id>"), registration_only = Some(true))` — costs ~0.00125 NEAR, permissionless.
3. **Victim (or attacker) calls**:
   ```
   ft_transfer(
     receiver_id = "<nbtc_contract_id>",
     amount     = 100_000,          // satoshis of nBTC
     memo       = Some("WITHDRAW_TO:bc1qvictimaddress...")
   )
   ```
4. **Execution path**:
   - `receiver_id == env::current_account_id()` → `true`
   - `memo.starts_with("WITHDRAW_TO:")` → `true`
   - `read_withdraw_relayer_address()` → `None`
   - Falls through to `self.token.ft_transfer(nbtc_contract_id, 100_000, memo)`
5. **Result**: 100,000 satoshi-units of nBTC are credited to the nBTC contract's own balance. No `burn`, `recover`, or admin function can retrieve them. The tokens are permanently lost.

### Citations

**File:** contracts/nbtc/src/lib.rs (L59-91)
```rust
    pub fn new(
        controller: AccountId,
        bridge_id: AccountId,
        name: String,
        symbol: String,
        icon: Option<String>,
        decimals: u8,
    ) -> Self {
        require!(!env::state_exists(), "Already initialized");
        let mut contract = Self {
            controller,
            bridge_id,
            token: FungibleToken::new(StorageKey::FungibleToken),
            metadata: LazyOption::new(
                StorageKey::Metadata,
                Some(&FungibleTokenMetadata {
                    spec: FT_METADATA_SPEC.to_string(),
                    name,
                    symbol,
                    icon,
                    reference: None,
                    reference_hash: None,
                    decimals,
                }),
            ),
        };

        contract
            .token
            .internal_register_account(&contract.bridge_id);

        contract
    }
```

**File:** contracts/nbtc/src/lib.rs (L158-159)
```rust
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
```

**File:** contracts/nbtc/src/lib.rs (L183-196)
```rust
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        // Legacy bridging flow used by Near Intents
        if receiver_id == env::current_account_id()
            && memo
                .as_ref()
                .is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
        {
            if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
                return self.token.ft_transfer(withdraw_relayer, amount, memo);
            }
        }

        self.token.ft_transfer(receiver_id, amount, memo);
    }
```

**File:** contracts/nbtc/src/lib.rs (L239-246)
```rust
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }
```

**File:** contracts/nbtc/src/lib.rs (L324-328)
```rust
    pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
        self.assert_controller();

        env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
    }
```
