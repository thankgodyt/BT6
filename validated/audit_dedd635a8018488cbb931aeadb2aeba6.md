### Title
Silent Token Loss via Unguarded Fallthrough in `ft_transfer` Legacy Withdrawal Path — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The `ft_transfer` override in the nBTC contract contains a special-case redirect for the legacy Near Intents withdrawal flow. When `receiver_id == env::current_account_id()` and the memo starts with `"WITHDRAW_TO:"`, the function is supposed to redirect the transfer to a configured `withdraw_relayer`. However, if `withdraw_relayer` is not set, the function silently falls through and executes `self.token.ft_transfer(receiver_id, amount, memo)` — transferring the user's nBTC to the nBTC contract's own account. Once there, the tokens are permanently locked with no recovery path.

---

### Finding Description

The `ft_transfer` implementation in `contracts/nbtc/src/lib.rs` overrides the NEP-141 standard to support a legacy bridging flow: [1](#0-0) 

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

When `withdraw_relayer` is `None` (not yet configured), the inner `if let` block is skipped entirely. Execution falls through to the final `self.token.ft_transfer(receiver_id, amount, memo)` call — where `receiver_id` is still `env::current_account_id()`, i.e., the nBTC contract itself.

The `withdraw_relayer` is set via `set_withdraw_relayer_address`, which is callable only by the controller: [2](#0-1) 

It is **not** initialized in the constructor: [3](#0-2) 

There is no view function to check whether it has been set, so users cannot detect the misconfiguration before calling `ft_transfer`.

The NEP-141 standard `FungibleToken::ft_transfer` checks `predecessor_account_id != receiver_id` (not `current_account_id != receiver_id`), so a transfer from a normal user to the nBTC contract itself passes this guard. The transfer then calls `internal_deposit(nbtc_contract, amount)`. For this to succeed rather than panic, the nBTC contract must be registered as an account in the token ledger. Any unprivileged account can accomplish this by calling `storage_deposit`: [4](#0-3) 

Once the nBTC contract is registered and `withdraw_relayer` is unset, any user who calls `ft_transfer(nbtc_contract, amount, "WITHDRAW_TO:...")` will have their tokens silently transferred into the nBTC contract's own balance. The contract has no function to recover tokens from its own balance — `burn` only withdraws from `bridge_id`: [5](#0-4) 

The tokens are permanently locked.

---

### Impact Explanation

Any nBTC holder who uses the legacy Near Intents withdrawal flow (`ft_transfer` with `receiver_id = nbtc_contract` and memo `"WITHDRAW_TO:..."`) while `withdraw_relayer` is unset will permanently lose their nBTC. The tokens are transferred into the nBTC contract's own ledger entry with no recovery mechanism. This constitutes **permanent locking of user funds**, matching the Critical impact category: *Significant loss, theft, destruction, or permanent locking of user or protocol funds.*

---

### Likelihood Explanation

- The `withdraw_relayer` is not set in the constructor and must be configured post-deployment by the controller. There is a deployment window during which it is unset.
- There is no view function exposing whether `withdraw_relayer` is set, so users cannot detect the misconfiguration.
- The legacy flow is an active, documented user-facing path ("Legacy bridging flow used by Near Intents"), making accidental use realistic.
- Pre-registering the nBTC contract as a token account requires only a small NEAR storage deposit — a trivial, permissionless action any attacker can perform.
- Likelihood is **Medium**: requires `withdraw_relayer` to be unset and the nBTC contract to be pre-registered, but both conditions are easily achievable and the user-facing flow is actively used.

---

### Recommendation

Replace the silent fallthrough with an explicit panic when `withdraw_relayer` is not configured:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        let withdraw_relayer = Self::read_withdraw_relayer_address()
            .expect("WITHDRAW_RELAYER_NOT_CONFIGURED");
        return self.token.ft_transfer(withdraw_relayer, amount, memo);
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

Additionally, add a guard in `ft_transfer` (and `ft_transfer_call`) that explicitly rejects `receiver_id == env::current_account_id()` outside the legacy path, analogous to the `require(_from != _recipient)` fix recommended in M-06.

---

### Proof of Concept

1. Deploy the nBTC contract. `withdraw_relayer` is unset (not initialized in `new()`).
2. Attacker calls `storage_deposit(account_id: Some(nbtc_contract_id), registration_only: Some(true))` with a small NEAR deposit. This registers the nBTC contract as a valid token account in the ledger.
3. User holds 1,000,000 nBTC (satoshis) and intends to withdraw via the legacy Near Intents flow. User calls:
   ```
   ft_transfer(
     receiver_id = nbtc_contract_id,
     amount     = 1_000_000,
     memo       = Some("WITHDRAW_TO:bc1q...")
   )
   ```
   attaching 1 yoctoNEAR.
4. Inside `ft_transfer`: `receiver_id == env::current_account_id()` is `true`; memo starts with `"WITHDRAW_TO:"` — condition matches.
5. `Self::read_withdraw_relayer_address()` returns `None` — the inner `if let` is skipped.
6. Execution falls through to `self.token.ft_transfer(nbtc_contract_id, 1_000_000, memo)`.
7. NEP-141 check: `predecessor (user) != receiver (nbtc_contract)` — passes.
8. `internal_deposit(nbtc_contract_id, 1_000_000)` — succeeds because the contract was pre-registered in step 2.
9. User's 1,000,000 nBTC are now in the nBTC contract's own ledger balance. No `burn`, `ft_transfer`, or admin function can recover them. Funds are permanently lost. [1](#0-0) [6](#0-5)

### Citations

**File:** contracts/nbtc/src/lib.rs (L58-91)
```rust
    #[init]
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

**File:** contracts/nbtc/src/lib.rs (L150-177)
```rust
    pub fn burn(
        &mut self,
        burn_account_id: AccountId,
        burn_amount: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
    ) {
        self.assert_bridge();
        self.token
            .internal_withdraw(&self.bridge_id, burn_amount.into());
        if relayer_fee.0 > 0 {
            if self.token.accounts.get(&relayer_account_id).is_none() {
                self.token.internal_register_account(&relayer_account_id);
            }
            self.token.internal_transfer(
                &self.bridge_id,
                &relayer_account_id,
                relayer_fee.into(),
                None,
            );
        }
        near_contract_standards::fungible_token::events::FtBurn {
            owner_id: &burn_account_id,
            amount: burn_amount,
            memo: None,
        }
        .emit();
    }
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

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
