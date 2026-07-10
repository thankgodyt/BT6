### Title
Relayer Fee Misdirected to `signer_account_id` Instead of `predecessor_account_id` in Burn and Mint Paths — (`contracts/satoshi-bridge/src/nbtc/burn.rs`, `contracts/satoshi-bridge/src/nbtc/mint.rs`)

---

### Summary

The bridge's `verify_withdraw_burn_promise` and `internal_mint_promise` both pass `env::signer_account_id()` as the `relayer_account_id` when calling `nbtc.burn()` and `nbtc.mint()`. The `#[trusted_relayer]` access gate and the `relayer_white_list` confirmation-reduction check both operate on `env::predecessor_account_id()` — the immediate caller. When a proxy relayer contract (whitelisted as a trusted relayer) submits a proof, `predecessor_account_id` is the proxy contract while `signer_account_id` is the human who signed the outer transaction. The relayer fee is therefore paid to the wrong account, mirroring the ZeroLocker pattern of using the caller identity (`msg.sender`) instead of the actual owner identity in a critical token operation.

---

### Finding Description

**Deposit path** — `internal_mint_promise` in `contracts/satoshi-bridge/src/nbtc/mint.rs` lines 19–28:

```rust
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .mint(
        recipient_id.clone(),
        mint_amount,
        protocol_fee,
        env::signer_account_id(),   // ← wrong identity
        relayer_fee,
        post_actions,
    )
```

**Withdrawal path** — `verify_withdraw_burn_promise` in `contracts/satoshi-bridge/src/nbtc/burn.rs` lines 17–24:

```rust
ext_nbtc::ext(config.nbtc_account_id.clone())
    .burn(
        btc_pending_info.account_id.clone(),
        btc_pending_info.burn_amount.into(),
        env::signer_account_id(),   // ← wrong identity
        relayer_fee.into(),
    )
```

The `nbtc.burn()` implementation in `contracts/nbtc/src/lib.rs` lines 160–169 then transfers `relayer_fee` tokens from the bridge balance to whichever account was passed as `relayer_account_id`:

```rust
self.token.internal_transfer(
    &self.bridge_id,
    &relayer_account_id,   // receives the fee
    relayer_fee.into(),
    None,
);
```

Meanwhile, the access-control gate uses `predecessor_account_id`. The `relayer_white_list` confirmation-reduction check in `contracts/satoshi-bridge/src/config.rs` lines 325–326 explicitly comments:

```rust
// Use predecessor_account_id to support both users and proxy protocols.
.contains(&env::predecessor_account_id())
```

This confirms the design intent: proxy contracts are valid trusted relayers. But the fee is paid to `signer_account_id` — the human who signed the outermost transaction — not to the proxy contract (`predecessor_account_id`) that actually performed the relay work.

---

### Impact Explanation

When a proxy relayer contract is whitelisted and publicly callable, any user who signs a transaction that routes through the proxy receives the relayer fee instead of the proxy contract. This constitutes:

- **Theft of relayer fees** from the proxy contract on every deposit and withdrawal it processes.
- **Broken economic invariant**: the entity that performs the relay work (the proxy contract) does not receive compensation; the fee accrues to an arbitrary transaction signer.

The `FtBurn` event also emits `burn_account_id` (the withdrawing user) as `owner_id` with `burn_amount` as the amount, while the actual net burn is `burn_amount` and an additional `relayer_fee` is transferred out of the bridge balance — creating a misleading on-chain record.

---

### Likelihood Explanation

The codebase explicitly documents support for proxy protocols as relayers (the comment in `get_confirmations`). Any proxy relayer contract that does not restrict who may call it allows an attacker to front-run legitimate relay submissions: the attacker signs the outer transaction, the proxy contract forwards the proof, and the relayer fee flows to the attacker. This is a realistic scenario for any integration (e.g., Omni Bridge integration) that wraps the bridge's verify functions.

---

### Recommendation

Replace `env::signer_account_id()` with `env::predecessor_account_id()` in both fee-payment call sites:

**`contracts/satoshi-bridge/src/nbtc/burn.rs`**
```rust
- env::signer_account_id(),
+ env::predecessor_account_id(),
```

**`contracts/satoshi-bridge/src/nbtc/mint.rs`**
```rust
- env::signer_account_id(),
+ env::predecessor_account_id(),
```

Also update the `VerifyWithdrawDetails` and `VerifyDepositDetails` event emissions in `verify_withdraw_burn_callback` and `mint_callback` to use `predecessor_account_id()` for consistency.

---

### Proof of Concept

1. DAO whitelists a publicly callable proxy relayer contract `proxy.near` as a trusted relayer.
2. A user deposits BTC; the corresponding UTXO and Merkle proof become available.
3. Attacker `attacker.near` calls `proxy.near::relay_deposit(proof)` before the legitimate operator does.
4. `proxy.near` calls `bridge.verify_deposit(proof)` — `predecessor_account_id = proxy.near`, `signer_account_id = attacker.near`.
5. Bridge calls `nbtc.mint(..., relayer_account_id = attacker.near, relayer_fee = X)`.
6. `nbtc.mint` mints `relayer_fee` tokens directly to `attacker.near`.
7. `proxy.near` receives zero fee despite performing the relay; `attacker.near` profits `X` nBTC per hijacked relay. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/burn.rs (L17-24)
```rust
        ext_nbtc::ext(config.nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_BURN_CALL)
            .burn(
                btc_pending_info.account_id.clone(),
                btc_pending_info.burn_amount.into(),
                env::signer_account_id(),
                relayer_fee.into(),
            )
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L19-28)
```rust
        ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
            .with_static_gas(GAS_FOR_MINT_CALL)
            .mint(
                recipient_id.clone(),
                mint_amount,
                protocol_fee,
                env::signer_account_id(),
                relayer_fee,
                post_actions,
            )
```

**File:** contracts/nbtc/src/lib.rs (L160-169)
```rust
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
```

**File:** contracts/satoshi-bridge/src/config.rs (L324-327)
```rust
            .relayer_white_list
            // Use predecessor_account_id to support both users and proxy protocols.
            .contains(&env::predecessor_account_id())
        {
```
