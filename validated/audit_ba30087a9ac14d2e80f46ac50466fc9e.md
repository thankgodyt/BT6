### Title
`env::signer_account_id()` (`tx.origin` Equivalent) Used as Caller Identity in `ft_on_transfer`, Enabling Trusted-Relayer Bypass and Storage-Balance Drain — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

In `near/omni-bridge/src/lib.rs`, the `ft_on_transfer` callback resolves the acting user via `env::signer_account_id()` — the NEAR equivalent of EVM's `tx.origin` — instead of the semantically correct `sender_id` parameter. This allows any contract that a trusted relayer (or any user with a storage balance) interacts with to impersonate that account toward the bridge, bypassing the trusted-relayer whitelist for fast transfers and draining storage balances.

---

### Finding Description

`ft_on_transfer` is the NEP-141 callback invoked by a token contract when `ft_transfer_call` is executed. The standard provides `sender_id` — the account that called `ft_transfer_call` — as a parameter. This is the correct identity of the acting user, analogous to `msg.sender` in EVM.

Instead, the bridge explicitly discards `sender_id` and reads `env::signer_account_id()`: [1](#0-0) 

```rust
// We can't trust sender_id to pay for storage as it can be spoofed.
let signer_id = env::signer_account_id();
```

`env::signer_account_id()` is the account that signed the *original* transaction — it propagates unchanged through any chain of cross-contract calls, exactly like `tx.origin`. A malicious intermediate contract can therefore call `ft_transfer_call` on any token while a victim is the transaction signer, and the bridge will treat the victim as the acting user.

This `signer_id` is then forwarded to two sensitive paths:

**Path 1 — `fast_fin_transfer` (trusted-relayer check):** [2](#0-1) [3](#0-2) 

The `signer_id` is passed as the relayer identity and immediately checked against the trusted-relayer whitelist. If the original transaction signer is a registered trusted relayer, the check passes regardless of which contract actually called `ft_transfer_call`.

**Path 2 — `init_transfer` (storage-balance payer):** [4](#0-3) [5](#0-4) 

The `signer_id` is used as the account whose pre-deposited storage balance is consumed to store the transfer message. A malicious contract can drain a victim's storage balance by routing a crafted `ft_transfer_call` through the victim's transaction.

---

### Impact Explanation

**Critical — Trusted-Relayer Authorization Bypass (`fast_fin_transfer`):**
Trusted relayers are whitelisted accounts permitted to front liquidity for fast transfers. If a trusted relayer signs any transaction that passes through a malicious (or compromised) intermediate contract, that contract can call `ft_transfer_call` with a crafted `FastFinTransferMsg`. The bridge will accept it as a legitimate fast transfer from the trusted relayer, bypassing the whitelist entirely. The malicious contract controls the `transfer_id`, `recipient`, `amount`, and `fee` fields, enabling it to execute fast transfers — and collect relayer fees — without being a registered relayer.

**Medium — Storage Balance Drain (`init_transfer`):**
Any user who has pre-deposited a storage balance in the bridge and signs a transaction that touches a malicious contract risks having that balance consumed to store an attacker-crafted transfer message. The balance is locked until the transfer is signed and removed, constituting a temporary but real loss of deposited NEAR.

---

### Likelihood Explanation

Trusted relayers are operational accounts that routinely interact with NEAR DeFi protocols, tooling contracts, and other on-chain infrastructure. Any such interaction where the relayer is the transaction signer is a viable attack surface. The attack requires no special permissions, no leaked keys, and no admin compromise — only that the victim signs a transaction that an attacker can intercept at the cross-contract call layer.

---

### Recommendation

Replace `env::signer_account_id()` with `sender_id` in `ft_on_transfer`. In the NEP-141 standard, `sender_id` is set by the token contract itself from the account that called `ft_transfer_call`; it is not attacker-controlled unless the token contract itself is malicious. Since the bridge only processes transfers from registered tokens, trusting `sender_id` is the correct and safe approach. The comment "We can't trust sender_id to pay for storage as it can be spoofed" conflates a malicious-token-contract threat (a separate, pre-existing risk) with the far more dangerous `tx.origin`-style impersonation introduced by `signer_account_id()`.

```rust
// Before (vulnerable):
let signer_id = env::signer_account_id();

// After (correct):
let signer_id = sender_id.clone();
```

---

### Proof of Concept

**Trusted-Relayer Bypass:**

1. Attacker deploys `MaliciousContract` on NEAR.
2. Attacker social-engineers or observes a trusted relayer (`relayer.near`) signing any transaction that calls `MaliciousContract` (e.g., a routine DeFi interaction).
3. `MaliciousContract::execute()` calls `token.ft_transfer_call(bridge, amount, FastFinTransfer { transfer_id: <real_pending_id>, recipient: attacker_addr, ... })`.
4. The token contract calls `bridge.ft_on_transfer(sender_id = MaliciousContract, amount, msg = FastFinTransfer{...})`.
5. Bridge executes: `let signer_id = env::signer_account_id(); // = relayer.near`.
6. `require!(self.is_trusted_relayer(&signer_id))` — **passes**, because `relayer.near` is whitelisted.
7. Fast transfer executes; `attacker_addr` receives tokens; `MaliciousContract` is recorded as having provided liquidity under `relayer.near`'s identity. [6](#0-5) [7](#0-6)

### Citations

**File:** near/omni-bridge/src/lib.rs (L253-283)
```rust
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
    }
```

**File:** near/omni-bridge/src/lib.rs (L566-584)
```rust
        if self
            .try_to_transfer_balance_from_message_account(
                &message_storage_account_id,
                NearToken::from_yoctonear(init_transfer_msg.native_token_fee.0),
                &signer_id,
                required_storage_balance,
            )
            .is_ok()
            || (self.has_storage_balance(
                &signer_id,
                required_storage_balance.saturating_add(NearToken::from_yoctonear(
                    init_transfer_msg.native_token_fee.0,
                )),
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
        {
            PromiseOrPromiseIndexOrValue::Value(
                self.init_transfer_internal(transfer_message, signer_id),
            )
```

**File:** near/omni-bridge/src/lib.rs (L749-757)
```rust
    fn fast_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: AccountId,
        fast_fin_transfer_msg: FastFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");

```
