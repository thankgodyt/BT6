### Title
`env::signer_account_id()` (`tx.origin` Analog) Used for Trusted-Relayer Authorization in `fast_fin_transfer` — (`File: near/omni-bridge/src/lib.rs`)

---

### Summary

`ft_on_transfer` reads `env::signer_account_id()` — NEAR's direct analog of Solidity's `tx.origin` — and passes it as `signer_id` to `fast_fin_transfer`, where it is used as the sole authorization check for the trusted-relayer gate. Any account that can induce a legitimate trusted relayer to sign a transaction that eventually calls `ft_transfer_call` on a token contract (e.g., via a malicious intermediary contract) will have that relayer's identity accepted by the bridge, bypassing the staking-based relayer requirement entirely.

---

### Finding Description

In `ft_on_transfer`, the code explicitly acknowledges that `sender_id` is untrusted and substitutes `env::signer_account_id()` instead:

```rust
// We can't trust sender_id to pay for storage as it can be spoofed.
let signer_id = env::signer_account_id();
``` [1](#0-0) 

`signer_id` is then forwarded directly into `fast_fin_transfer`:

```rust
BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
    self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
}
``` [2](#0-1) 

Inside `fast_fin_transfer`, `signer_id` is the **only** check that gates the trusted-relayer path:

```rust
require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");
``` [3](#0-2) 

In NEAR's execution model:
- `env::predecessor_account_id()` = the immediate calling contract (`msg.sender` analog)
- `env::signer_account_id()` = the original transaction signer (`tx.origin` analog)

When a trusted relayer signs a transaction that calls an intermediary contract, and that intermediary contract calls `ft_transfer_call` on a token, the bridge's `ft_on_transfer` is invoked with `env::signer_account_id()` returning the trusted relayer's account — even though the relayer did not intend to execute a fast transfer. The intermediary contract controls the `FastFinTransferMsg` payload entirely.

---

### Impact Explanation

An attacker who controls an intermediary contract and can induce a trusted relayer to call it gains the ability to:

1. **Execute `fast_fin_transfer` without being a registered trusted relayer**, bypassing the staking and waiting-period requirements enforced by `apply_for_trusted_relayer`.
2. **Set the `relayer` field in `FastFinTransferMsg` to their own account**, so that when `claim_fee` is later called with the legitimate proof, the fee is paid to the attacker rather than the legitimate relayer.
3. **Mark arbitrary `transfer_id`s as fast-finalized**, potentially front-running legitimate relayers and stealing their fee entitlement on real pending cross-chain transfers.

The `fast_fin_transfer` path sends real bridged tokens to the specified `recipient` and records a `FastTransfer` entry that gates subsequent fee claims: [4](#0-3) 

The `relayer_id` recorded in the fast transfer entry is taken directly from the attacker-controlled message field, not from the actual caller: [5](#0-4) 

---

### Likelihood Explanation

Trusted relayers are automated bots that interact with multiple contracts on NEAR. An attacker can deploy a contract that mimics a legitimate DeFi protocol, liquidity pool, or bridge component. When a trusted relayer interacts with it (e.g., to claim rewards, swap tokens, or perform routine operations), the malicious contract executes `ft_transfer_call` with a crafted `FastFinTransfer` payload. The attacker needs only to hold a small amount of the bridged token to fund the call. No private key compromise or social engineering beyond deploying a plausible-looking contract is required.

---

### Recommendation

Replace `env::signer_account_id()` with `env::predecessor_account_id()` for the purpose of relayer authorization. The `predecessor_account_id` is the direct caller of `ft_on_transfer` (the token contract), but the actual initiator of the `ft_transfer_call` is the `sender_id` parameter provided by the token contract — which is set by the token contract itself from its own `predecessor_account_id` at the time of the `ft_transfer_call`. For trusted NEP-141 tokens, `sender_id` is reliable for authorization. Alternatively, require that the `FastFinTransfer` message include an explicit relayer field that is verified against a separate on-chain signature, decoupling authorization from the transaction origin entirely.

---

### Proof of Concept

1. Eve deploys `MaliciousContract` on NEAR. It holds a small balance of a bridged token (e.g., `wETH.omni-bridge.near`).
2. `MaliciousContract` exposes a public method `trigger()`.
3. Inside `trigger()`, it calls:
   ```
   wETH.ft_transfer_call(
     receiver_id = omni-bridge.near,
     amount = X,
     msg = FastFinTransfer {
       transfer_id = <real pending transfer ID>,
       recipient = <victim or Eve's address>,
       amount = X,
       fee = { fee: Y, native_fee: 0 },
       relayer = Eve's account,
       ...
     }
   )
   ```
4. Alice (a trusted relayer) calls `MaliciousContract.trigger()` as part of routine operations.
5. The call chain: `Alice → MaliciousContract → wETH.ft_transfer_call → omni-bridge.ft_on_transfer`.
6. Inside `ft_on_transfer`: `env::signer_account_id()` = Alice. `is_trusted_relayer(Alice)` = `true`.
7. `fast_fin_transfer` executes: tokens are sent to the specified recipient; a `FastTransfer` record is created with `relayer = Eve`.
8. When the legitimate proof is later submitted via `claim_fee`, the fee is paid to Eve's account. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L748-756)
```rust
    #[allow(clippy::needless_pass_by_value)]
    fn fast_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: AccountId,
        fast_fin_transfer_msg: FastFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(self.is_trusted_relayer(&signer_id), "Relayer is not active");
```

**File:** near/omni-bridge/src/lib.rs (L782-789)
```rust
        let fast_transfer = FastTransfer {
            token_id: token_id.clone(),
            recipient: fast_fin_transfer_msg.recipient.clone(),
            amount: U128(denormalized_amount),
            fee: denormalized_fee,
            transfer_id: fast_fin_transfer_msg.transfer_id,
            msg: fast_fin_transfer_msg.msg,
        };
```

**File:** near/omni-bridge/src/lib.rs (L821-825)
```rust
                    .fast_fin_transfer_to_near_callback(
                        &fast_transfer,
                        signer_id,
                        fast_fin_transfer_msg.relayer,
                    ),
```
