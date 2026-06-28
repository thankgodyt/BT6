### Title
Missing Token Registration Check in `init_transfer` Allows Permanent Locking of Unregistered Tokens - (`starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract's `init_transfer` function accepts any arbitrary ERC20 `token_address` without verifying that the token is registered/supported by the bridge. This is directly analogous to the external report's pattern: a validation check that exists at one stage of the lifecycle (`deploy_token` registers tokens) is absent at a later stage (`init_transfer`). Tokens locked via `init_transfer` with an unregistered address will never be finalized on NEAR, and no recovery mechanism exists, resulting in permanent freezing of user funds.

### Finding Description

The Starknet bridge has a two-step token lifecycle:

1. **Registration step** (`deploy_token`): A token is registered by writing bidirectional mappings `starknet_to_near_token` and `near_to_starknet_token`. Only tokens that appear in these mappings are "known" to the bridge. [1](#0-0) 

2. **Transfer initiation step** (`init_transfer`): The function accepts any `token_address`. It uses `is_bridge_token` only to decide between burn vs. lock — **not** to validate that the token is registered at all. [2](#0-1) 

The `is_bridge_token` helper only checks the `starknet_to_near_token` mapping (i.e., whether the token was deployed by the bridge as a wrapped asset). For native Starknet tokens (the `else` branch), there is zero check that the token is registered or supported. [3](#0-2) 

When a user calls `init_transfer` with an unregistered token:
- The bridge executes `transfer_from(caller, contract, amount)` — tokens are locked.
- An `InitTransfer` event is emitted with the unregistered `token_address`.
- A relayer submits this to NEAR's `fin_transfer_callback`, which looks up `self.token_decimals.get(&init_transfer.token)` and panics with `TokenDecimalsNotFound` because the token was never registered on NEAR. [4](#0-3) 

- The Starknet contract has no `refund`, `unlock`, or recovery function. The only outbound token flow is `fin_transfer`, which requires a valid NEAR MPC signature — a signature that will never be produced for an unregistered token. [5](#0-4) 

### Impact Explanation

Tokens locked in the Starknet bridge via `init_transfer` with an unregistered `token_address` are permanently frozen. There is no on-chain recovery path: `fin_transfer` requires a NEAR MPC signature, which NEAR will never produce for an unregistered token, and no admin rescue function exists. This matches the allowed impact of **permanent freezing of bridged funds**.

### Likelihood Explanation

Any unprivileged user can call `init_transfer` directly with an arbitrary `token_address`. This can happen accidentally (user provides wrong token address) or deliberately (attacker tricks a user via a malicious UI). The missing check is on a public, permissionless entry point with no access control beyond the pause flag.

### Recommendation

Add a registration check in `init_transfer` for the non-bridge-token path. Specifically, verify that the `token_address` has a corresponding NEAR token ID in the `starknet_to_near_token` mapping (or a separate whitelist), and revert if it is not registered:

```cairo
fn init_transfer(ref self: ContractState, token_address: ContractAddress, ...) {
    assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');
    // Add: verify token is registered
    assert(
        self.is_bridge_token(token_address) ||
        self.starknet_to_near_token.read(token_address).len() > 0,
        'ERR_TOKEN_NOT_REGISTERED'
    );
    ...
}
```

Alternatively, maintain a separate whitelist of supported native tokens that is updated when `log_metadata` is called.

### Proof of Concept

1. Deploy any arbitrary ERC20 token `FAKE` on Starknet (not registered via `deploy_token`).
2. Approve the Starknet `OmniBridge` to spend `FAKE` tokens.
3. Call `init_transfer(FAKE_address, 1000, 0, 0, "near:recipient.near", "")`.
4. The bridge executes `FAKE.transfer_from(caller, bridge, 1000)` — tokens are locked.
5. A relayer submits the proof to NEAR's `fin_transfer`. NEAR's `fin_transfer_callback` calls `self.token_decimals.get(&init_transfer.token)` and panics — the transfer is rejected.
6. The 1000 `FAKE` tokens remain permanently locked in the Starknet bridge with no recovery path. [6](#0-5) [7](#0-6)

### Citations

**File:** starknet/src/omni_bridge.cairo (L224-225)
```text
            self.starknet_to_near_token.write(contract_address, payload.token.clone());
            self.near_to_starknet_token.write(token_id_hash, contract_address);
```

**File:** starknet/src/omni_bridge.cairo (L242-263)
```text
        fn fin_transfer(
            ref self: ContractState, signature: Signature, payload: TransferMessagePayload,
        ) {
            assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');

            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L281-307)
```text
        fn init_transfer(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u128,
            fee: u128,
            native_fee: u128,
            recipient: ByteArray,
            message: ByteArray,
        ) {
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

**File:** starknet/src/omni_bridge.cairo (L378-380)
```text
        fn is_bridge_token(self: @ContractState, token_address: ContractAddress) -> bool {
            self.starknet_to_near_token.read(token_address).len() > 0
        }
```

**File:** near/omni-bridge/src/lib.rs (L705-718)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```
