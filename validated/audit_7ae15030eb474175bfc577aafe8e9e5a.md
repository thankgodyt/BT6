### Title
`ft_transfer_call` Does Not Implement the Legacy Withdrawal Redirect Logic Present in `ft_transfer` — (File: `contracts/nbtc/src/lib.rs`)

---

### Summary
The nBTC contract overrides `ft_transfer` to redirect transfers with a `WITHDRAW_TO:` memo prefix to the configured withdraw relayer, but does not apply the same override to `ft_transfer_call`. Any integrator or user who calls `ft_transfer_call` expecting the same legacy withdrawal behavior will not have their tokens redirected to the withdraw relayer — the call will fail and tokens will be returned, silently breaking the legacy withdrawal path.

---

### Finding Description
In `contracts/nbtc/src/lib.rs`, the `FungibleTokenCore` implementation overrides `ft_transfer` with special redirect logic for the legacy Near Intents withdrawal flow:

```rust
// contracts/nbtc/src/lib.rs lines 183–196
fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer(withdraw_relayer, amount, memo);
        }
    }
    self.token.ft_transfer(receiver_id, amount, memo);
}
```

However, `ft_transfer_call` is **not** overridden with the same logic — it delegates unconditionally to the standard implementation:

```rust
// contracts/nbtc/src/lib.rs lines 198–207
fn ft_transfer_call(
    &mut self,
    receiver_id: AccountId,
    amount: U128,
    memo: Option<String>,
    msg: String,
) -> PromiseOrValue<U128> {
    self.token.ft_transfer_call(receiver_id, amount, memo, msg)
}
```

This is the direct analog to the Hats M-12 vulnerability: `ft_transfer` is overridden with special conditional logic, but the sibling transfer function `ft_transfer_call` is not, producing inconsistent behavior between the two standard NEP-141 transfer entry points.

When a caller sends `ft_transfer_call` with `receiver_id = nbtc_contract` and `memo = "WITHDRAW_TO:..."`:

1. The standard implementation transfers tokens to the nbtc contract itself (not the withdraw relayer).
2. The nbtc contract does not implement `ft_on_transfer`, so the cross-contract call panics.
3. `ft_resolve_transfer` is invoked and returns the tokens to the sender.

The legacy withdrawal is never processed. The tokens are returned, but the operation silently fails in a way that is invisible to callers who expect parity between the two transfer functions.

---

### Impact Explanation
The invariant that "a transfer to the nbtc contract with a `WITHDRAW_TO:` memo triggers a legacy withdrawal to the configured relayer" holds only for `ft_transfer`. It is violated for `ft_transfer_call`. Any integrator (e.g., a DeFi protocol or wallet) that uses `ft_transfer_call` for the legacy withdrawal path will receive a failed callback and returned tokens rather than a processed withdrawal. This is a publicly reachable invariant-violation in the production token contract. No direct fund theft occurs (tokens are returned), but the bridge's documented legacy withdrawal path is broken for one of the two standard NEP-141 transfer entry points.

---

### Likelihood Explanation
Low. The legacy flow is documented as using `ft_transfer`. However, both `ft_transfer` and `ft_transfer_call` are standard NEP-141 entry points, and integrators building on top of the nBTC token (e.g., Near Intents or other DeFi protocols) may reasonably attempt to use `ft_transfer_call` for the same purpose, especially when they need the `ft_on_transfer` callback pattern. The inconsistency is reachable by any unprivileged token holder.

---

### Recommendation
Override `ft_transfer_call` in the nBTC contract to apply the same legacy withdrawal redirect logic as `ft_transfer`:

```rust
fn ft_transfer_call(
    &mut self,
    receiver_id: AccountId,
    amount: U128,
    memo: Option<String>,
    msg: String,
) -> PromiseOrValue<U128> {
    if receiver_id == env::current_account_id()
        && memo.as_ref().is_some_and(|m| m.starts_with(WITHDRAW_MEMO_PREFIX))
    {
        if let Some(withdraw_relayer) = Self::read_withdraw_relayer_address() {
            return self.token.ft_transfer_call(withdraw_relayer, amount, memo, msg);
        }
    }
    self.token.ft_transfer_call(receiver_id, amount, memo, msg)
}
```

---

### Proof of Concept

1. Deploy the nBTC contract and configure a withdraw relayer address via `set_withdraw_relayer_address`.
2. Register the nbtc contract itself as a token holder via `storage_deposit(account_id: nbtc_contract)`.
3. As a token holder, call:
   ```
   ft_transfer_call(
     receiver_id: nbtc_contract,
     amount: "1000",
     memo: "WITHDRAW_TO:btc1qxxx...",
     msg: ""
   )
   ```
4. Observe: tokens are transferred to the nbtc contract, `ft_on_transfer` panics (not implemented), `ft_resolve_transfer` returns tokens to sender. The withdraw relayer is never notified.
5. Repeat with `ft_transfer` using the same arguments: tokens are correctly redirected to the withdraw relayer.

The two standard NEP-141 transfer functions produce divergent outcomes for identical inputs, confirming the inconsistency. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/nbtc/src/lib.rs (L37-38)
```rust
const WITHDRAW_RELAYER_ADDRESS: &[u8] = b"WITHDRAW_RELAYER_ADDRESS";
const WITHDRAW_MEMO_PREFIX: &str = "WITHDRAW_TO:";
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

**File:** contracts/nbtc/src/lib.rs (L198-207)
```rust
    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }
```

**File:** contracts/nbtc/src/lib.rs (L354-356)
```rust
    fn read_withdraw_relayer_address() -> Option<AccountId> {
        env::storage_read(WITHDRAW_RELAYER_ADDRESS).and_then(|data| borsh::from_slice(&data).ok())
    }
```
