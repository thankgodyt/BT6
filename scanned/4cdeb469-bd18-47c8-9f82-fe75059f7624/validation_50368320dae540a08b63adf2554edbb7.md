Let me look at a few more details to complete the analysis.

### Title
Silent `send_tokens` Failure in `utxo_fin_transfer_fast` Causes Permanent BTC Token Loss — (`near/omni-bridge/src/lib.rs`)

### Summary

In `utxo_fin_transfer_fast`, when a NEAR-destination fast BTC transfer is finalized, the fast transfer record is removed from state **before** the relayer reimbursement is sent, and the reimbursement promise is detached with no failure callback. If `send_tokens` fails for any reason, the BTC tokens transferred by the connector are permanently locked in the bridge with no recovery path. The developers themselves flagged this with a `TODO` comment at the exact call site.

---

### Finding Description

The flow for a NEAR-destination fast BTC transfer finalization is:

1. The BTC connector calls `ft_on_transfer` on the bridge, which routes to `utxo_fin_transfer` [1](#0-0) 

2. Because a fast transfer status exists, execution branches immediately to `utxo_fin_transfer_fast` and **returns early**, skipping the `add_fin_utxo_transfer` call that would record the UTXO in `finalised_utxo_transfers`: [2](#0-1) 

3. Inside `utxo_fin_transfer_fast`, when the destination is NEAR, `remove_fast_transfer` is called first, permanently deleting the fast transfer record from state: [3](#0-2) 

4. Then `send_tokens` is called with `.detach()` — no callback, no failure handling: [4](#0-3) 

5. The function unconditionally returns `U128(0)` to the connector, signaling that all tokens were consumed: [5](#0-4) 

The developer-inserted `TODO` comment at the call site explicitly acknowledges the unresolved failure case: [6](#0-5) 

If `send_tokens` fails (e.g., `ft_transfer` panics because the relayer account has no storage registration on the token contract), the following invariants are simultaneously broken:

- The fast transfer entry is gone — no retry is possible via the fast path.
- The UTXO is absent from `finalised_utxo_transfers` — but the connector already received `U128(0)` and considers the transfer finalized, so it will not re-submit.
- The tokens remain in the bridge contract with no pending transfer, no fast transfer entry, and no mechanism to recover them.

`send_tokens` for a non-deployed, non-wNEAR token calls `ft_transfer` on the token contract: [7](#0-6) 

`ft_transfer` panics if the recipient has no storage registration on the NEP-141 token contract. Because the promise is detached, this panic is silently swallowed.

---

### Impact Explanation

The BTC tokens sent by the connector to the bridge are permanently frozen. The relayer receives nothing. The user already received tokens from the relayer during the fast transfer phase, so the user is unaffected — but the bridge's token balance is permanently reduced by the transfer amount. This constitutes **permanent loss of bridged funds** (Critical scope: "permanent freezing of bridged funds").

---

### Likelihood Explanation

The relayer is a trusted entity, but the failure condition is reachable:

- After performing a fast transfer, the relayer may have zero balance on the BTC token contract (they sent all their tokens to the recipient).
- A relayer with zero balance can call `storage_unregister` on the token contract, removing their registration.
- If finalization occurs after unregistration, `ft_transfer` to the relayer panics, the detached promise swallows the failure, and the tokens are lost.
- This can happen accidentally (relayer housekeeping) or deliberately (a malicious relayer sacrificing their reimbursement to grief the protocol).

The `TODO` comment at line 2484 confirms the developers are aware this case is unhandled.

---

### Recommendation

Replace the fire-and-forget `.detach()` pattern with a proper callback that handles failure. On failure, either:

- Re-insert the fast transfer record and re-add the UTXO to `finalised_utxo_transfers` so the transfer can be retried, or
- Credit the relayer's internal bridge storage balance so they can withdraw later.

The state mutation (`remove_fast_transfer`) should only be committed after `send_tokens` succeeds, mirroring the pattern used in `fast_fin_transfer_to_near_callback` → `resolve_fast_transfer`: [8](#0-7) 

---

### Proof of Concept

```
1. Deploy bridge + BTC connector on local testnet.
2. Register relayer as trusted; relayer performs fast_fin_transfer to NEAR recipient R,
   sending all of relayer's BTC tokens (relayer balance → 0).
3. Relayer calls storage_unregister on the BTC token contract (balance is 0, so allowed).
4. BTC UTXO arrives; connector calls ft_on_transfer → utxo_fin_transfer → utxo_fin_transfer_fast.
5. remove_fast_transfer executes (fast transfer entry deleted).
6. send_tokens calls ft_transfer(relayer, amount) → panics (relayer not registered).
   Promise is detached; panic is silently ignored.
7. utxo_fin_transfer_fast returns U128(0); connector marks UTXO as processed.
8. Assert: relayer balance = 0, fast_transfers map has no entry, finalised_utxo_transfers
   has no entry, bridge holds the BTC tokens with no recovery path.
```

### Citations

**File:** near/omni-bridge/src/lib.rs (L2102-2106)
```rust
        } else if msg.is_empty() {
            ext_token::ext(token)
                .with_attached_deposit(ONE_YOCTO)
                .with_static_gas(FT_TRANSFER_GAS)
                .ft_transfer(recipient, amount, None)
```

**File:** near/omni-bridge/src/lib.rs (L2456-2489)
```rust
    fn utxo_fin_transfer(
        &mut self,
        token_id: AccountId,
        amount: U128,
        signer_id: &AccountId,
        sender_id: &AccountId,
        utxo_fin_transfer_msg: UtxoFinTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        let origin_chain = self
            .get_utxo_chain_by_token(&token_id)
            .near_expect(BridgeError::UtxoConfigMissing);
        let config = self
            .utxo_chain_connectors
            .get(&origin_chain)
            .near_expect(BridgeError::UtxoConfigMissing);
        require!(
            sender_id == &config.connector,
            BridgeError::SenderIsNotConnector.as_ref()
        );

        let fast_transfer = FastTransfer::from_utxo_transfer(
            utxo_fin_transfer_msg.clone(),
            token_id.clone(),
            amount,
            origin_chain,
        );

        if let Some(status) = self.get_fast_transfer_status(&fast_transfer.id()) {
            // TODO: check how to deal with failed send_tokens
            return self.utxo_fin_transfer_fast(fast_transfer, status, utxo_fin_transfer_msg);
        }

        let required_storage_balance =
            self.add_fin_utxo_transfer(&utxo_fin_transfer_msg.get_transfer_id(origin_chain));
```

**File:** near/omni-bridge/src/lib.rs (L2529-2531)
```rust
        let amount = if fast_transfer.get_destination_chain() == ChainKind::Near {
            self.remove_fast_transfer(&fast_transfer.id());
            fast_transfer.amount
```

**File:** near/omni-bridge/src/lib.rs (L2542-2548)
```rust
        self.send_tokens(
            fast_transfer.token_id.clone(),
            fast_transfer_status.relayer,
            amount,
            "",
        )
        .detach();
```

**File:** near/omni-bridge/src/lib.rs (L2560-2560)
```rust
        PromiseOrPromiseIndexOrValue::Value(U128(0))
```

**File:** near/omni-bridge/src/lib.rs (L2877-2912)
```rust

```
