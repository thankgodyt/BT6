Audit Report

## Title
Detached Burn Promise with Insufficient Gas Enables Cross-Chain Token Supply Inflation - (File: `near/omni-bridge/src/lib.rs`)

## Summary
`burn_tokens_if_needed` schedules a cross-contract `burn` call using `.detach()`, permanently discarding the promise result. With only 3 TGas allocated — less than the typical cost of a NEP-141 burn — the burn can silently fail while `InitTransferEvent` and `FastTransferEvent` are unconditionally committed to state. Relayers observing these events will finalize the transfer on the destination chain, minting tokens there while the source tokens remain un-burned in the bridge, permanently inflating total cross-chain supply.

## Finding Description
`burn_tokens_if_needed` is defined at `near/omni-bridge/src/lib.rs:1806–1813`:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)  // 3 TGas
            .burn(amount)
            .detach();   // result never observed
    }
}
```

`BURN_TOKEN_GAS` is `Gas::from_tgas(3)` (line 72). By contrast, `MINT_TOKEN_GAS` is 5 TGas (line 73), and a standard NEP-141 burn involves at least one storage read, one storage write (balance update), one total-supply write, and event emission — routinely exceeding 3 TGas.

This function is called in three critical paths, all of which advance protocol state before the burn result could ever be observed:

1. **`init_transfer_internal` (lines 1850–1863):** calls `burn_tokens_if_needed`, then unconditionally emits `InitTransferEvent`. The transfer message is already stored and the nonce already incremented in the same execution frame.

2. **`fast_fin_transfer_to_other_chain` (line 932):** calls `burn_tokens_if_needed`, then stores the fast-transfer record and emits `FastTransferEvent`.

3. **`resolve_fast_transfer` (line 904):** calls `burn_tokens_if_needed` inside a `#[private]` callback, but the fast-transfer record is removed and the callback returns without reverting if the burn silently fails.

Because `.detach()` severs the promise chain, NEAR's runtime never delivers a failure receipt back to the bridge contract. There is no callback, no retry, and no revert path. The emitted events are immutable on-chain log entries that relayers treat as authoritative.

## Impact Explanation
This directly matches the Critical impact class: **escrow mis-accounting / balance manipulation that changes user or protocol balances** and **unauthorized minting**.

If the detached burn fails:
- `InitTransferEvent` / `FastTransferEvent` is on-chain and immutable.
- Relayers call `finTransfer` on the destination EVM/Solana/Starknet bridge, minting `amount` tokens to the recipient.
- The source bridge-deployed tokens are **not destroyed**; they remain in the bridge contract's balance.
- Total circulating supply of the bridged token is permanently inflated by `amount` — a cross-chain double-spend.

## Likelihood Explanation
- 3 TGas is below the realistic execution cost of a NEP-141 burn on the omni-token contract (storage reads/writes + event emission). The protocol's own `MINT_TOKEN_GAS` is already 5 TGas for a comparable operation.
- The entry point (`ft_transfer_call` → `ft_on_transfer` → `init_transfer_internal`) is publicly reachable by any unprivileged token holder — no special role required.
- Failure is silent: no on-chain error is surfaced, no retry exists, and the event is committed before the burn result could be observed.
- If 3 TGas is genuinely insufficient, the condition is deterministic and reproducible on every transfer of a bridge-deployed token, making it systemic rather than edge-case.

## Recommendation
1. **Replace `.detach()` with a chained callback** that checks the burn result. If the burn fails, the callback must revert the stored transfer message, decrement the nonce, and return the tokens to the sender.
2. **Increase `BURN_TOKEN_GAS`** to at least 10–15 TGas to cover realistic omni-token burn execution (storage writes, event emission, cross-contract overhead).
3. **Audit all other `.detach()` call sites** in the bridge for the same fire-and-forget pattern on state-critical operations.

## Proof of Concept
1. User holds `N` units of a bridge-deployed token (e.g., `weth.omni.near`).
2. User calls `ft_transfer_call` on the token contract, transferring `N` tokens to the bridge with a valid `InitTransferMsg` targeting an EVM chain.
3. The bridge's `ft_on_transfer` runs `init_transfer_internal`:
   - Transfer message stored, nonce incremented (state committed).
   - `burn_tokens_if_needed` schedules `burn(N)` with 3 TGas and `.detach()`.
   - `InitTransferEvent` emitted (state committed).
   - `ft_on_transfer` returns `U128(0)` — no refund to user.
4. The detached burn promise executes but fails due to gas exhaustion (3 TGas < actual burn cost). No callback exists; the bridge never learns of the failure.
5. A relayer observes `InitTransferEvent` and calls `finTransfer` on the EVM `OmniBridge`, minting `N` tokens to the user's EVM address.
6. The source `N` tokens were never burned — they remain in the bridge contract's balance.
7. Total supply of the bridged token is permanently inflated by `N` units.

**Verification test plan:** Deploy the omni-token contract and the bridge on a local NEAR sandbox. Instrument the token contract's `burn` function to log actual gas consumption. Call `ft_transfer_call` with a valid transfer message and confirm via sandbox receipts that the burn receipt status is `Failure` (gas exhausted) while `InitTransferEvent` appears in the transaction logs. Confirm the bridge's token balance is non-zero post-transfer.