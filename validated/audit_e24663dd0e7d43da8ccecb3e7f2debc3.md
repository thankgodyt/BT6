### Title
Unset `withdraw_relayer_address` Silently Redirects Legacy-Withdrawal Tokens Into the nBTC Contract Itself — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary

The nBTC contract's `ft_transfer` override implements a legacy Near-Intents withdrawal path. When `withdraw_relayer_address` is not configured (its default, unset state), a user who calls `ft_transfer` with the `WITHDRAW_MEMO_PREFIX` memo directed at the nBTC contract address receives no revert; instead the call silently falls through and transfers the tokens to the nBTC contract itself. If the nBTC contract account is registered as a token holder (which any party can arrange via the public `storage_deposit` call), those tokens are permanently locked with no recovery path.

---

### Finding Description

`ft_transfer` in the nBTC contract contains a special branch for the legacy Near-Intents withdrawal flow:

```rust
// contracts/nbtc/src/lib.rs  (FungibleTokenCore impl)
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
        // ← no else-branch: falls through silently
    }

    self.token.ft_transfer(receiver_id, amount, memo);   // receiver_id == nBTC contract
}
``` [1](#0-0) 

`withdraw_relayer_address` is stored in raw contract storage under the key `WITHDRAW_RELAYER_ADDRESS` and is read back with:

```rust
fn read_withdraw_relayer_address() -> Option<AccountId> {
    env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
}
``` [2](#0-1) 

The value is **never written during `new()`**:

```rust
pub fn new(controller: AccountId, bridge_id: AccountId, ...) -> Self {
    // no withdraw_relayer_address initialisation
    ...
    contract.token.internal_register_account(&contract.bridge_id);
    contract
}
``` [3](#0-2) 

It can only be set later via `set_withdraw_relayer_address`, which is a separate, optional configuration step:

```rust
pub fn set_withdraw_relayer_address(&mut self, relayer: &AccountId) {
    self.assert_controller();
    env::storage_write(WITHDRAW_RELAYER_ADDRESS, &borsh::to_vec(relayer).unwrap());
}
``` [4](#0-3) 

When the relayer is absent, the outer `if` block is entered (both conditions are true), the inner `if let Some` guard is skipped, and control falls through to the unconditional `self.token.ft_transfer(receiver_id, amount, memo)` where `receiver_id` is `env::current_account_id()` — the nBTC contract itself. The NEAR FT standard's `ft_transfer` will succeed if that account is registered as a token holder. Registration is open to anyone:

```rust
fn storage_deposit(&mut self, account_id: Option<AccountId>, ...) -> StorageBalance {
    self.token.storage_deposit(account_id, registration_only)
}
``` [5](#0-4) 

Once the nBTC contract account holds tokens, there is no function in the contract that can retrieve or burn them from that balance — `burn()` withdraws only from `bridge_id`, not from the nBTC contract's own account. [6](#0-5) 

---

### Impact Explanation

Any nBTC holder who invokes the legacy Near-Intents withdrawal path (`ft_transfer` to the nBTC contract address with a `"WITHDRAW_TO:…"` memo) while `withdraw_relayer_address` is unset will have their tokens silently transferred into the nBTC contract itself. Those tokens are permanently irrecoverable — no burn, no admin rescue path exists for that balance. This constitutes permanent, irreversible destruction of user funds backed by real BTC, matching the **Medium** impact class: *permanent burning below backed supply / stuck bridge state requiring operator intervention*.

---

### Likelihood Explanation

`withdraw_relayer_address` is absent by default and must be set as a separate post-deployment step. Any deployment window where this step is skipped, or any future migration that clears the value, opens the window. An adversary can pre-register the nBTC contract as a token holder (a permissionless, low-cost `storage_deposit` call) to ensure the silent transfer succeeds rather than reverting. Users relying on the Near-Intents legacy flow have no on-chain signal that the relayer is unconfigured; they will proceed and lose funds.

---

### Recommendation

Add an explicit revert when the legacy-withdrawal branch is entered but no relayer is configured, mirroring the pattern of the original report's recommendation:

```rust
if receiver_id == env::current_account_id()
    && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
{
    let relayer = Self::read_withdraw_relayer_address()
        .unwrap_or_else(|| env::panic_str("withdraw_relayer_address not configured"));
    return self.token.ft_transfer(relayer, amount, memo);
}
self.token.ft_transfer(receiver_id, amount, memo);
```

This ensures that an unconfigured relayer produces a hard revert rather than a silent mis-delivery.

---

### Proof of Concept

1. Deploy the nBTC contract without calling `set_withdraw_relayer_address` (default state).
2. Adversary calls `storage_deposit(Some(<nbtc_contract_account_id>), None)` with a small NEAR deposit — this registers the nBTC contract itself as a valid token-holder account.
3. Victim holds nBTC and, following the Near-Intents legacy UI, calls:
   ```
   ft_transfer(
       receiver_id = <nbtc_contract_account_id>,
       amount      = <victim_amount>,
       memo        = Some("WITHDRAW_TO:<victim_btc_address>")
   )
   ```
   with 1 yoctoNEAR attached.
4. `ft_transfer` enters the legacy branch (both conditions true), finds `withdraw_relayer_address == None`, skips the inner guard, and falls through to `self.token.ft_transfer(<nbtc_contract_account_id>, amount, memo)`.
5. The underlying FT transfer succeeds (account is registered from step 2). Victim's nBTC is now held by the nBTC contract itself.
6. No function in the nBTC contract can recover or burn tokens from that balance. Funds are permanently lost.

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
