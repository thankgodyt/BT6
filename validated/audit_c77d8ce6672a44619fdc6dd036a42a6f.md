### Title
Relayer Fee Misdirected to `env::signer_account_id()` (NEAR's `tx.origin`) Instead of `env::predecessor_account_id()` (`msg.sender`) in `internal_mint_promise` — (File: contracts/satoshi-bridge/src/nbtc/mint.rs)

---

### Summary

`internal_mint_promise` passes `env::signer_account_id()` — NEAR Protocol's direct analog of Ethereum's `tx.origin` — as the `relayer_account_id` when calling the nBTC `mint` function. When a smart-contract account acts as the relayer and calls `verify_deposit`, the relayer fee is credited to the original transaction key-signer rather than to the calling contract. The smart-contract relayer loses its fee on every such deposit.

---

### Finding Description

In `contracts/satoshi-bridge/src/nbtc/mint.rs`, `internal_mint_promise` constructs the cross-contract call to the nBTC token contract:

```rust
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_MINT_CALL)
    .mint(
        recipient_id.clone(),
        mint_amount,
        protocol_fee,
        env::signer_account_id(),   // ← relayer_account_id: NEAR's tx.origin
        relayer_fee,
        post_actions,
    )
```

In NEAR Protocol:

| NEAR API | Ethereum equivalent | Meaning |
|---|---|---|
| `env::predecessor_account_id()` | `msg.sender` | The immediate caller of this contract |
| `env::signer_account_id()` | `tx.origin` | The original key-signer of the transaction |

When a simple (non-contract) account calls `verify_deposit`, the two values are identical and no harm occurs. However, when a smart-contract relayer (e.g., a relayer aggregator, a proxy, or any contract-based automation) calls `verify_deposit`, `env::predecessor_account_id()` is the relayer contract while `env::signer_account_id()` is the human key that signed the outer transaction. The nBTC `mint` function receives the signer as `relayer_account_id` and pays `relayer_fee` to that signer — not to the relayer contract that performed the work.

The same incorrect value is also emitted in the `mint_callback` event:

```rust
Event::VerifyDepositDetails {
    ...
    relayer_account_id: env::signer_account_id(),   // ← wrong account logged
    relayer_fee,
    ...
}
```

---

### Impact Explanation

Every time a smart-contract relayer calls `verify_deposit`, the `relayer_fee` (denominated in nBTC) is transferred to the human key-signer rather than to the relayer contract. The relayer contract receives nothing for its work. Over many deposits this constitutes a steady, silent drain of funds away from the relayer contract and toward an unintended recipient. The user's nBTC (`recipient_id`) is unaffected; only the relayer's compensation is misdirected.

This matches the **Low** allowed impact: *publicly reachable invariant-violation in a production bridge/token path without direct theft of user funds*.

---

### Likelihood Explanation

NEAR's ecosystem increasingly supports contract-based accounts and proxy patterns. Any relayer infrastructure that routes calls through a smart contract (aggregators, DAO-controlled relayers, automated keeper contracts) will silently lose its fee on every deposit it processes. The entry path is fully permissionless — no special role is required to call `verify_deposit` — so any smart-contract relayer that is whitelisted or that submits proofs with the extra confirmation delta will trigger this path.

---

### Recommendation

Replace `env::signer_account_id()` with `env::predecessor_account_id()` in both the `mint` call and the `VerifyDepositDetails` event inside `internal_mint_promise` and `mint_callback`:

```rust
// Before
env::signer_account_id()

// After
env::predecessor_account_id()
```

This ensures the relayer fee is always credited to the account that actually submitted the proof, regardless of whether that account is a simple key or a smart contract.

---

### Proof of Concept

1. Deploy a smart-contract relayer `relayer.near` on NEAR. The relayer contract's `submit_deposit` method calls `satoshi_bridge.verify_deposit(...)` internally.
2. A human key `operator.near` signs and submits a transaction calling `relayer.near::submit_deposit(...)`.
3. Inside `verify_deposit`, `internal_mint_promise` is reached:
   - `env::predecessor_account_id()` → `relayer.near` (the actual relayer)
   - `env::signer_account_id()` → `operator.near` (the key signer)
4. The nBTC `mint` function receives `operator.near` as `relayer_account_id` and transfers `relayer_fee` nBTC to `operator.near`.
5. `relayer.near` receives 0 nBTC as its fee despite having submitted the proof.
6. Repeated across N deposits: `relayer.near` loses `N × relayer_fee` nBTC; `operator.near` gains it. [1](#0-0) [2](#0-1)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L19-29)
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
            .then(
```

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L74-83)
```rust
        Event::VerifyDepositDetails {
            recipient_id: &recipient_id,
            mint_amount,
            protocol_fee,
            relayer_account_id: env::signer_account_id(),
            relayer_fee,
            success: is_success,
        }
        .emit();
        is_success
```
