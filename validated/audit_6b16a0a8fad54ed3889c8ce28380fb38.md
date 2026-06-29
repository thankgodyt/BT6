Audit Report

## Title
Detached `burn` Promise in `burn_tokens_if_needed` Enables Silent Failure and Token Supply Inflation — (`near/omni-bridge/src/lib.rs`)

## Summary
`burn_tokens_if_needed` schedules a cross-contract `burn` call with `.detach()`, permanently discarding the promise result. Because the burn outcome is never checked, any failure is silently swallowed: `InitTransferEvent` is still emitted and the transfer record is committed, allowing a relayer to finalize the transfer on the destination chain and mint tokens there while the original tokens remain unburned in the bridge contract — inflating total circulating supply.

## Finding Description
`burn_tokens_if_needed` at L1806–1813 uses `.detach()` unconditionally:

```rust
fn burn_tokens_if_needed(&self, token: AccountId, amount: U128) {
    if self.is_deployed_token(&token) {
        ext_token::ext(token)
            .with_static_gas(BURN_TOKEN_GAS)   // 3 TGas only
            .burn(amount)
            .detach();                          // result silently discarded
    }
}
```

`BURN_TOKEN_GAS` is defined at L72 as `Gas::from_tgas(3)` — an extremely tight budget for a cross-contract call that must execute `assert_controller()` plus `internal_withdraw` (storage reads, balance check, write, and NEP-141 Transfer event emission).

This helper is called in four critical sites, none of which check the burn result:

- **`init_transfer_internal` (L1851)**: After the detached burn, `InitTransferEvent` is unconditionally emitted (L1863) and `U128(0)` is returned to `ft_transfer_call`, signalling full token consumption. A failed burn leaves tokens in the bridge while the event is on-chain.
- **`resolve_fast_transfer` (L904)**: The in-code comment explicitly states *"Burn the tokens to ensure the locked tokens are not double-minted"* — the burn is the sole guard against double-minting, yet its failure is invisible.
- **`fast_fin_transfer_to_other_chain` (L932)**: Same pattern before emitting the fast-transfer event.
- **`fin_transfer_send_tokens_callback` (L1703)**: Same pattern in the refund path.

The token contract's `burn` function (L146–151 of `near/omni-token/src/lib.rs`) can fail if: (a) the 3 TGas budget is exhausted by NEAR runtime overhead for the cross-contract dispatch plus storage I/O, or (b) the bridge's registered balance in the token contract is zero or inconsistent, causing `internal_withdraw` to panic. The project's own security checklist in `near/CLAUDE.md` L228 explicitly states: *"Detached promises should only be used for non-critical operations"* — the burn is unambiguously critical.

## Impact Explanation
This matches the Critical allowed impact: **unauthorized minting / double-spending of bridged funds**. For bridge-deployed tokens (e.g., wETH minted by the bridge on NEAR), the invariant is that outbound tokens must be burned on NEAR before equivalent tokens are minted on the destination chain. A silent burn failure breaks this invariant: the `InitTransferEvent` is on-chain, a relayer submits proof to the EVM bridge and mints `amount` tokens on the destination chain, and the original `amount` tokens remain unburned in `bridge.near`. Total circulating supply is permanently inflated by `amount`. The same outcome applies in `resolve_fast_transfer`, where the relayer's fronted tokens are not burned yet the destination-chain mint proceeds.

## Likelihood Explanation
The entry point is `ft_transfer_call` on any bridge-deployed token — a fully public, unpermissioned call available to any token holder. No special role is required. The burn failure vector via gas exhaustion is realistic: 3 TGas is allocated for a cross-contract call whose base scheduling overhead alone consumes ~2 TGas on NEAR, leaving ~1 TGas for `assert_controller` and `internal_withdraw` storage operations. Additionally, any accounting inconsistency in the token contract (e.g., from a prior bug or race condition) causes `internal_withdraw` to panic, silently failing the burn. Because `.detach()` hides the failure, it may go undetected until a supply discrepancy is observed on-chain.

## Recommendation
Replace `.detach()` with a proper callback that checks the burn result and reverts the transfer if the burn failed. In `init_transfer_internal`, chain the burn promise and add a callback that panics (causing `ft_transfer_call` to refund) if the burn fails. In `resolve_fast_transfer` and `fast_fin_transfer_to_other_chain`, await the burn result before committing the transfer record or emitting events. Additionally, increase `BURN_TOKEN_GAS` from 3 TGas to at least 10–15 TGas to provide a safe margin for cross-contract call overhead and storage I/O.

## Proof of Concept
1. Attacker holds `N` units of a bridge-deployed token (e.g., `weth.bridge.near`).
2. Attacker calls `ft_transfer_call(bridge.near, N, msg=InitTransfer{recipient: eth_address, ...})` with sufficient total gas.
3. Token contract transfers `N` tokens to `bridge.near` and calls `ft_on_transfer`.
4. Bridge calls `init_transfer_internal` → `burn_tokens_if_needed` → schedules `burn(N).detach()` with 3 TGas.
5. Due to gas exhaustion (3 TGas insufficient for cross-contract overhead + `internal_withdraw`) or token contract panic, the burn fails — silently.
6. Bridge emits `InitTransferEvent{amount: N, recipient: eth_address}` and returns `U128(0)` to `ft_transfer_call` (no refund to attacker).
7. A relayer picks up the event and calls `finTransfer` on the EVM bridge, minting `N` wETH to `eth_address`.
8. Result: `N` wETH exist on Ethereum AND `N` weth tokens remain unburned in `bridge.near` — total supply permanently inflated by `N`.

A local integration test can reproduce this by deploying the bridge and token contracts on a NEAR sandbox, configuring the token as a deployed token, then calling `ft_transfer_call` with a gas budget crafted to exhaust the 3 TGas burn allocation (or by patching the token contract to panic in `burn`), and asserting that `InitTransferEvent` was emitted while the bridge's token balance remains `N`.