### Title
Unregistered Token Accepted in Starknet `init_transfer` Causes Permanent Fund Loss - (File: starknet/src/omni_bridge.cairo)

### Summary
The Starknet `init_transfer` function accepts any ERC20 token via `transfer_from` without verifying that the token is registered in the bridge's cross-chain token registry. When a relayer attempts to finalize the transfer on NEAR, the `fin_transfer_callback` panics because the token has no registered decimals entry, leaving the user's tokens permanently locked in the Starknet bridge contract with no recovery path.

### Finding Description
In `starknet/src/omni_bridge.cairo`, the `init_transfer` function performs only two checks before accepting tokens: pause state and fee validity. For non-bridge tokens it executes `transfer_from` to lock the user's tokens in the contract:

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
```

There is no check that `token_address` has been registered in the bridge's cross-chain token registry (i.e., that a corresponding NEAR token ID and decimals mapping exist). Any ERC20 token whose `transfer_from` succeeds will be accepted and locked.

On the NEAR side, `fin_transfer_callback` in `near/omni-bridge/src/lib.rs` requires the token to have a registered decimals entry:

```rust
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
```

If the token was never registered via the `logMetadata` → `deployToken` / `bind_token` flow, this call panics and the NEAR finalization fails. The Starknet bridge has no cancel or refund mechanism for stuck deposits, so the tokens are permanently frozen.

### Impact Explanation
A user who calls `init_transfer` on Starknet with a valid ERC20 token that has not been registered in the bridge loses their tokens permanently. The Starknet contract accepts and locks the tokens, the NEAR finalization reverts with `ERR_TOKEN_DECIMALS_NOT_FOUND`, and no on-chain path exists to recover the locked balance. This is a direct, permanent loss of bridged funds.

### Likelihood Explanation
The Starknet bridge is permissionless at the `init_transfer` entry point. Any user can call it with any ERC20 token. A user who attempts to bridge a token that is listed on Starknet but has not yet completed the NEAR-side registration process (or a token that was de-registered) will trigger this path. No privileged access or special conditions are required beyond holding the token and calling the public function.

### Recommendation
Add a registration check at the start of `init_transfer` in `starknet/src/omni_bridge.cairo`. Before accepting tokens, verify that the `token_address` has a known mapping to a NEAR token (e.g., via a `token_address_to_near_id` storage map populated during `deploy_token`). If the token is not registered, revert with a clear error rather than locking funds that cannot be finalized.

### Proof of Concept
1. Deploy or obtain any ERC20 token on Starknet that has **not** been registered in the Omni Bridge (no `logMetadata` + `deployToken` flow completed on NEAR).
2. Approve the Starknet bridge contract to spend `amount` of that token.
3. Call `init_transfer(token_address, amount, fee, 0, near_recipient, "")` on the Starknet bridge.
4. The branch at [1](#0-0)  executes `transfer_from`, locking the tokens in the bridge. No registration check is performed.
5. A relayer submits the Wormhole VAA to NEAR's `fin_transfer`. The callback at [2](#0-1)  calls `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)`, which panics because the token was never registered.
6. The NEAR transaction reverts. The Starknet bridge holds the tokens with no refund or cancel function. The user's funds are permanently lost.

The deposit-side check gap is at: [3](#0-2) 

The withdrawal-side enforcement that has no corresponding deposit guard is at: [2](#0-1)

### Citations

**File:** starknet/src/omni_bridge.cairo (L290-307)
```text
            assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

            assert(amount > 0, 'ERR_ZERO_AMOUNT');
            assert(fee < amount, 'ERR_INVALID_FEE');

            let origin_nonce = self.current_origin_nonce.read() + 1;
            self.current_origin_nonce.write(origin_nonce);

            let caller = get_caller_address();

            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```

**File:** near/omni-bridge/src/lib.rs (L715-718)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```
