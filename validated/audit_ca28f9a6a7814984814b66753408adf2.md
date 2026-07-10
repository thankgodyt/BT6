### Title
Uninitialized `withdraw_relayer_address` Causes Silent Token Misdirection in Legacy Bridging Flow — (`contracts/nbtc/src/lib.rs`)

### Summary
The `WITHDRAW_RELAYER_ADDRESS` raw-storage slot is never written during contract initialization. When unset, `ft_transfer` silently falls through and sends tokens to the nBTC contract itself rather than reverting. An unprivileged attacker can pre-register the nBTC contract's own FT account via the public `storage_deposit` entrypoint, after which any user invoking the legacy Near-Intents bridging path loses their tokens permanently.

### Finding Description

`set_withdraw_relayer_address` writes the relayer into raw storage under the key `WITHDRAW_RELAYER_ADDRESS`: [1](#0-0) 

`read_withdraw_relayer_address` reads that slot and returns `None` when it has never been written: [2](#0-1) 

The `new()` constructor never calls `set_withdraw_relayer_address` and never writes `WITHDRAW_RELAYER_ADDRESS`, so the slot is absent from storage on every fresh deployment: [3](#0-2) 

The overridden `ft_transfer` contains the legacy bridging path: [4](#0-3) 

When `receiver_id == env::current_account_id()` and the memo starts with `"WITHDRAW_TO:"`, the inner `if let Some(...)` branch is taken only when the relayer is set. When it is `None` (the default), execution falls through to `self.token.ft_transfer(receiver_id, amount, memo)` — a transfer whose `receiver_id` is the nBTC contract itself. This is the unintended path: the user intended a withdrawal relay, but instead their tokens are deposited into the nBTC contract's own FT balance.

The `new()` constructor registers only `bridge_id` as an FT account: [5](#0-4) 

The nBTC contract's own account ID is not registered, so in the default state the fallthrough transfer panics and reverts — tokens are safe. However, `storage_deposit` is a public, permissionless entrypoint: [6](#0-5) 

Any caller can invoke `storage_deposit(Some(nbtc_contract_id), None)` to register the nBTC contract's own FT account. Once registered, the fallthrough transfer succeeds and tokens are credited to the nBTC contract's own balance. No function in the contract can recover them: `burn` withdraws from `bridge_id`, not from the nBTC contract's own account, and there is no other transfer-out path.

### Impact Explanation

Tokens sent via the legacy bridging flow while `withdraw_relayer_address` is unset and the nBTC contract's own account is registered are permanently locked. There is no administrative recovery function. This constitutes a permanent, irrecoverable loss of user funds — matching the "stuck bridge state requiring operator intervention" / "permanent burning below backed supply" Medium impact class.

### Likelihood Explanation

The preconditions are:
1. `withdraw_relayer_address` is unset — the default state on every fresh deployment.
2. The nBTC contract's own FT account is registered — a one-time, low-cost action any unprivileged account can perform via `storage_deposit`.
3. A user invokes `ft_transfer(nbtc_contract_id, amount, "WITHDRAW_TO:…")` — the documented Near Intents integration path.

An attacker needs only to call `storage_deposit` once (step 2) before any Near Intents user interacts with the contract. The user's action (step 3) is the normal, expected Near Intents flow. The combination is realistic whenever the bridge is deployed without immediately configuring the relayer address.

### Recommendation

Replace the silent fallthrough with an explicit panic when the relayer is not configured:

```rust
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        let relayer = Self::read_withdraw_relayer_address()
            .unwrap_or_else(|| env::panic_str("Withdraw relayer address not configured"));
        return self.token.ft_transfer(relayer, amount, memo);
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

This ensures the legacy bridging path either succeeds as intended or reverts with a clear error, and never silently misdirects tokens to the contract itself.

### Proof of Concept

1. Deploy the nBTC contract. `withdraw_relayer_address` is absent from storage (never written by `new()`).
2. Attacker calls `storage_deposit(account_id: Some("<nbtc_contract_id>"), registration_only: None)` — publicly accessible, costs only the storage deposit.
3. Near Intents user calls `ft_transfer(receiver_id: "<nbtc_contract_id>", amount: U128(1_000_000), memo: Some("WITHDRAW_TO:bc1q…"))` with 1 yoctoNEAR attached.
4. `read_withdraw_relayer_address()` returns `None`; the inner `if let Some(...)` branch is skipped.
5. Execution reaches `self.token.ft_transfer(nbtc_contract_id, amount, memo)`.
6. The nBTC contract's own FT account exists (step 2); the standard transfer succeeds.
7. `1_000_000` satoshi-worth of nBTC is credited to the nBTC contract's own balance. No function can move it out. Funds are permanently lost.

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
