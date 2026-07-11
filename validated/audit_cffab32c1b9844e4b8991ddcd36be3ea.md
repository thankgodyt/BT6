### Title
Relayer Fee Misdirected to Transaction Signer Instead of Actual Relayer via `signer_account_id()` Misuse - (File: contracts/satoshi-bridge/src/nbtc/mint.rs)

### Summary

In `contracts/satoshi-bridge/src/nbtc/mint.rs`, the bridge uses `env::signer_account_id()` to identify the relayer for fee attribution instead of `env::predecessor_account_id()`. In NEAR, `signer_account_id()` is the original transaction initiator, while `predecessor_account_id()` is the immediate caller. When a whitelisted relayer is a smart contract, any user who calls that relayer contract becomes the `signer_account_id()` and receives the relayer fee — the actual relayer contract (the `predecessor`) receives nothing.

### Finding Description

In `internal_mint_promise`, the `relayer_account_id` argument passed to the nBTC `mint` call is set to `env::signer_account_id()`:

```rust
// contracts/satoshi-bridge/src/nbtc/mint.rs, lines 19-28
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_MINT_CALL)
    .mint(
        recipient_id.clone(),
        mint_amount,
        protocol_fee,
        env::signer_account_id(),   // ← wrong identity
        relayer_fee,
        post_actions,
    )
``` [1](#0-0) 

The same identity is echoed in the `mint_callback` event:

```rust
// contracts/satoshi-bridge/src/nbtc/mint.rs, line 78
relayer_account_id: env::signer_account_id(),
``` [2](#0-1) 

In the nBTC contract, `mint` then mints `relayer_fee` tokens directly to that `relayer_account_id`:

```rust
// contracts/nbtc/src/lib.rs, lines 140-142
if relayer_fee.0 > 0 {
    self.mint_inner(&relayer_account_id, relayer_fee);
}
``` [3](#0-2) 

The whitelist authorization check (enforced by the `#[trusted_relayer]` macro on the bridge) correctly gates on `predecessor_account_id()` — the relayer contract. But the fee is paid to `signer_account_id()` — the user who called the relayer contract. These are two different accounts whenever the relayer is a smart contract. [4](#0-3) 

**Analog to the Kakarot finding:** The Kakarot bug uses `caller_code_address` (the code being executed) instead of `caller_address` (the actual execution context) for authorization, allowing an unauthorized party to benefit from a privileged identity. Here, the bridge uses `signer_account_id()` (the original transaction initiator) instead of `predecessor_account_id()` (the actual relayer) for fee attribution — the same class of identity confusion between "who initiated the chain" vs "who is the immediate privileged actor."

### Impact Explanation

The relayer fee is freshly minted nBTC paid out of the deposit's fee budget. When a whitelisted relayer is a smart contract, the fee is minted to the user who called the relayer contract, not to the relayer contract itself. The relayer contract receives zero compensation for its work. Over time this:

- Systematically drains relayer revenue, disincentivizing honest relayer operation.
- Allows any user to capture relayer fees by routing their deposit proof submission through a whitelisted relayer contract.

This matches the **Medium** allowed impact: bypass of bridge fee/policy controls with economic harm to bridge infrastructure participants.

### Likelihood Explanation

NEAR accounts are all capable of being smart contracts. If any whitelisted relayer is deployed as a contract (e.g., a relayer aggregator, a DAO-controlled relayer, or a multi-sig relayer), the condition is met. The attack requires only that the attacker submit a valid deposit proof through such a relayer — a fully public, permissionless action for any user with a real BTC deposit.

### Recommendation

Replace `env::signer_account_id()` with `env::predecessor_account_id()` in `internal_mint_promise` so the fee is attributed to the actual relayer that submitted the proof:

```rust
// contracts/satoshi-bridge/src/nbtc/mint.rs
ext_nbtc::ext(self.internal_config().nbtc_account_id.clone())
    .with_static_gas(GAS_FOR_MINT_CALL)
    .mint(
        recipient_id.clone(),
        mint_amount,
        protocol_fee,
        env::predecessor_account_id(),  // ← correct: the actual relayer
        relayer_fee,
        post_actions,
    )
```

Apply the same fix to the `relayer_account_id` field in the `mint_callback` event emission.

### Proof of Concept

1. Operator whitelists `relayer-contract.near` as a trusted relayer (a smart contract).
2. Attacker (`attacker.near`) obtains a valid BTC deposit and its Merkle proof.
3. Attacker calls `relayer-contract.near::submit_proof(proof)`, which internally calls `satoshi-bridge.near::verify_deposit_v2(...)`.
4. Inside the bridge: `predecessor_account_id()` = `relayer-contract.near` (passes whitelist check); `signer_account_id()` = `attacker.near`.
5. Bridge calls `nbtc.near::mint(..., relayer_account_id = attacker.near, relayer_fee = X, ...)`.
6. nBTC mints `X` tokens to `attacker.near`. `relayer-contract.near` receives nothing.
7. Attacker repeats for every deposit they submit through the whitelisted relayer contract, capturing all relayer fees. [5](#0-4) [6](#0-5)

### Citations

**File:** contracts/satoshi-bridge/src/nbtc/mint.rs (L10-40)
```rust
    pub fn internal_mint_promise(
        &self,
        recipient_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_fee: U128,
        pending_utxo_info: PendingUTXOInfo,
        post_actions: Option<Vec<PostAction>>,
    ) -> Promise {
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
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_MINT_CALL_BACK)
                    .mint_callback(
                        recipient_id.clone(),
                        mint_amount,
                        protocol_fee,
                        relayer_fee,
                        pending_utxo_info,
                    ),
            )
    }
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

**File:** contracts/nbtc/src/lib.rs (L126-148)
```rust
    pub fn mint(
        &mut self,
        mint_account_id: AccountId,
        mint_amount: U128,
        protocol_fee: U128,
        relayer_account_id: AccountId,
        relayer_fee: U128,
        post_actions: Option<Vec<PostAction>>,
    ) {
        self.assert_bridge();
        self.mint_inner(&mint_account_id, mint_amount);
        if protocol_fee.0 > 0 {
            self.mint_inner(&self.bridge_id.clone(), protocol_fee);
        }
        if relayer_fee.0 > 0 {
            self.mint_inner(&relayer_account_id, relayer_fee);
        }
        if let Some(post_actions) = post_actions {
            Self::ext(env::current_account_id())
                .handle_post_actions(mint_account_id, post_actions)
                .detach();
        }
    }
```

**File:** contracts/satoshi-bridge/src/lib.rs (L175-179)
```rust
#[trusted_relayer(
    bypass_roles(Role::DAO, Role::UnrestrictedRelayer),
    manager_roles(Role::DAO, Role::RelayerManager),
    config_roles(Role::DAO)
)]
```
