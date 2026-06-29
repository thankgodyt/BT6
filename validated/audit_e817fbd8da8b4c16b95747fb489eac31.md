Audit Report

## Title
`init_transfer()` Accepts Unregistered Native Token Addresses Without Registration Check, Causing Permanent Fund Loss - (File: starknet/src/omni_bridge.cairo)

## Summary

The `init_transfer()` function in `starknet/src/omni_bridge.cairo` accepts any caller-supplied `token_address` and transfers tokens from the caller to the bridge contract without verifying that the token is registered in the bridge's token registry. For any token that is not a bridge-deployed token (i.e., not in `starknet_to_near_token`), the function executes `transfer_from` and emits an `InitTransfer` event, but the corresponding NEAR-side finalization will always panic with `TokenNotRegistered` because no registration path exists for native Starknet tokens. The contract has no rescue or admin-withdrawal function, making the locked funds permanently irrecoverable.

## Finding Description

In `starknet/src/omni_bridge.cairo`, `init_transfer()` (L281–331) accepts `token_address` from the caller and uses `is_bridge_token(token_address)` (L300) solely to select the transfer mechanism — burn for bridge-deployed tokens, `transfer_from` for all others. There is no check that the token is registered or supported before accepting it.

`is_bridge_token()` (L378–380) returns `true` only when `starknet_to_near_token.read(token_address).len() > 0`. The only function that writes to `starknet_to_near_token` is `deploy_token()` (L224), which deploys a new bridge-owned token contract. There is no function in the contract to register a pre-existing native Starknet ERC20 token into `starknet_to_near_token`.

For any token not deployed by the bridge, the `else` branch (L303–307) executes:
```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
```
The tokens are now held by the bridge. An `InitTransfer` event is emitted (L316–330), giving the user no indication of failure.

On the NEAR side, when a relayer calls `fin_transfer`, `get_token_id()` (L1368–1375 of `near/omni-bridge/src/lib.rs`) looks up the Starknet address in `token_address_to_id`. Since the token was never registered there, it panics with `BridgeError::TokenNotRegistered`. The transfer is never finalized.

The contract exposes no admin-withdrawal, token-rescue, or refund function. The full public interface is: `log_metadata`, `deploy_token`, `fin_transfer`, `init_transfer`, `upgrade_token`, `set_pause_flags`, `pause_all`, `upgrade`, and view functions — none of which can recover arbitrary ERC20 tokens held by the contract.

## Impact Explanation

Any user who calls `init_transfer()` with a legitimate Starknet ERC20 token that has not been registered via `deploy_token()` will have their tokens permanently locked in the bridge contract. The cross-chain transfer cannot be finalized on NEAR, there is no refund mechanism, and no admin path exists to recover the funds. This constitutes permanent freezing of bridged funds, matching the Critical allowed impact: *"Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."*

## Likelihood Explanation

The entry point is fully public and requires no special role or privilege. Any Starknet user holding a native ERC20 token that has not been registered in the bridge (e.g., a token whose `log_metadata` was submitted but `deploy_token` not yet executed on NEAR, a newly listed token, or simply a mistaken address) can trigger this path. The `else` branch in `init_transfer()` is clearly designed to handle native Starknet tokens, but the absence of a registration mechanism and the absence of a registration guard means any token can be silently accepted and permanently locked. No collusion, special access, or unrealistic precondition is required.

## Recommendation

Add an explicit registration check in `init_transfer()` before accepting any token transfer. Verify that the supplied `token_address` is either a bridge-deployed token or is present in `starknet_to_near_token` as a registered native token. Reject with a clear error if neither condition holds:

```cairo
fn init_transfer(ref self: ContractState, token_address: ContractAddress, ...) {
    assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

    // Add registration check:
    let is_registered = self.is_bridge_token(token_address)
        || self.starknet_to_near_token.read(token_address).len() > 0;
    assert(is_registered, 'ERR_TOKEN_NOT_REGISTERED');

    // ... rest of function unchanged
}
```

Additionally, introduce a privileged function (e.g., `register_native_token`) that allows the admin to register pre-existing Starknet ERC20 tokens into `starknet_to_near_token`, enabling the `else` branch to be used safely.

## Proof of Concept

1. Alice holds 1000 units of `TokenX`, a legitimate Starknet ERC20 not registered in the bridge (not in `starknet_to_near_token`).
2. Alice approves the bridge contract to spend 1000 `TokenX`.
3. Alice calls `init_transfer(token_address=TokenX, amount=1000, fee=0, native_fee=0, recipient="alice.near", message="")`.
4. The function passes the pause check, amount/fee checks, and increments the nonce (L290–296).
5. `is_bridge_token(TokenX)` returns `false` — `starknet_to_near_token.read(TokenX).len() == 0` (L378–380).
6. The `else` branch executes `transfer_from(alice, bridge, 1000)` successfully (L303–307). Alice's 1000 `TokenX` are now held by the bridge.
7. An `InitTransfer` event is emitted with `token_address = TokenX` (L316–330). Alice sees a successful-looking transaction.
8. A relayer picks up the event and submits `fin_transfer` on NEAR.
9. NEAR's `get_token_id(&OmniAddress::Starknet(TokenX))` (L1368–1375) calls `token_address_to_id.get(address).near_expect(BridgeError::TokenNotRegistered)` — panics.
10. The transfer is never finalized. Alice's 1000 `TokenX` are permanently locked in the Starknet bridge contract with no recovery path.

A local integration test can reproduce this by: (a) deploying the Starknet bridge and a mock ERC20 without calling `deploy_token` for it, (b) calling `init_transfer` with the mock ERC20 address, (c) confirming the `transfer_from` succeeds and tokens are held by the bridge, and (d) confirming the NEAR-side `fin_transfer` panics with `TokenNotRegistered`.