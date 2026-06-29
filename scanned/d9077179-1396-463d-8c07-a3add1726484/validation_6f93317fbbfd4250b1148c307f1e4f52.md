### Title
Native Fee (STRK) Tokens Permanently Locked in Starknet `OmniBridge` Contract with No Withdrawal Mechanism - (File: starknet/src/omni_bridge.cairo)

### Summary
The Starknet `OmniBridge` contract collects STRK native fee tokens from users during `init_transfer`, but provides no function to withdraw or distribute these accumulated tokens. Every call to `init_transfer` with `native_fee > 0` permanently locks STRK in the contract.

### Finding Description
In `starknet/src/omni_bridge.cairo`, the `init_transfer` function accepts a `native_fee` parameter and, when non-zero, pulls STRK tokens from the caller directly into the contract address:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

The complete `IOmniBridge` interface exposes only these functions: `log_metadata`, `deploy_token`, `fin_transfer`, `init_transfer`, `upgrade_token`, `set_pause_flags`, `pause_all`, and three view functions. [2](#0-1) 

None of these functions withdraw or distribute the accumulated STRK. The `fin_transfer` function only mints/transfers the main bridged token to the recipient — it performs no STRK transfer to any `fee_recipient`: [3](#0-2) 

The `fee_recipient` field in the `FinTransfer` event is emitted as metadata only; no STRK is actually sent to it on the Starknet side. There is no `claim_fee`, `withdraw`, or admin rescue function anywhere in the contract.

By contrast, the NEAR-side `omni-bridge` contract does have a `claim_fee` / `send_fee_internal` path that mints native fee tokens to the relayer after proof verification: [4](#0-3) 

This NEAR-side mechanism handles native fees for chains like EVM and Solana, but the Starknet contract itself has no symmetric mechanism to release the STRK it holds.

The CLAUDE.md for Starknet explicitly acknowledges native fees exist ("Optional native token fees in `init_transfer` (e.g., for gas)") but documents no withdrawal path: [5](#0-4) 

### Impact Explanation
Every `init_transfer` call with `native_fee > 0` permanently locks STRK tokens in the Starknet OmniBridge contract. These tokens can never be recovered by the protocol, relayers, or users. This constitutes permanent freezing of fee funds on Starknet and fee mis-accounting — relayers who are supposed to earn native fees for facilitating Starknet → NEAR transfers receive nothing on the Starknet side, and the STRK is irrecoverably lost.

### Likelihood Explanation
The `native_fee` parameter is a first-class, documented feature of `init_transfer`. Any user bridging from Starknet to NEAR who sets `native_fee > 0` (as intended to compensate relayers for gas) triggers the lock. This is a normal, expected usage path, not an edge case.

### Recommendation
Add a fee-withdrawal function to the Starknet `OmniBridge` contract that allows an authorized party (e.g., `DEFAULT_ADMIN_ROLE` or a designated fee recipient) to transfer accumulated STRK native fees out of the contract. Alternatively, mirror the NEAR-side `claim_fee` pattern: upon `fin_transfer` finalization, forward the corresponding `native_fee` amount to the `fee_recipient` specified in the payload.

### Proof of Concept
1. User calls `init_transfer(token_address, 1000, 10, 50, "near:recipient.near", "")` on the Starknet OmniBridge.
2. The contract executes `IERC20(strk_token).transfer_from(user, contract_address, 50)` — 50 STRK enters the contract.
3. A relayer finalizes the transfer on NEAR via `fin_transfer`, earning the fee on the NEAR side.
4. The 50 STRK sitting in the Starknet contract has no claimable path. No function in `IOmniBridge` can move it. It is permanently locked.
5. Repeating across all users who pay native fees causes unbounded STRK accumulation with zero recoverability.

### Citations

**File:** starknet/src/omni_bridge.cairo (L8-32)
```text
#[starknet::interface]
pub trait IOmniBridge<TContractState> {
    fn log_metadata(ref self: TContractState, token: ContractAddress);
    fn deploy_token(ref self: TContractState, signature: Signature, payload: MetadataPayload);
    fn fin_transfer(
        ref self: TContractState, signature: Signature, payload: TransferMessagePayload,
    );
    fn init_transfer(
        ref self: TContractState,
        token_address: ContractAddress,
        amount: u128,
        fee: u128,
        native_fee: u128,
        recipient: ByteArray,
        message: ByteArray,
    );
    fn upgrade_token(
        ref self: TContractState, token_address: ContractAddress, new_class_hash: ClassHash,
    );
    fn set_pause_flags(ref self: TContractState, flags: u8);
    fn pause_all(ref self: TContractState);
    fn get_token_address(self: @TContractState, token_id: ByteArray) -> ContractAddress;
    fn is_bridge_token(self: @TContractState, token_address: ContractAddress) -> bool;
    fn is_transfer_finalised(self: @TContractState, nonce: u64) -> bool;
}
```

**File:** starknet/src/omni_bridge.cairo (L242-279)
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

            self
                .emit(
                    Event::FinTransfer(
                        FinTransfer {
                            origin_chain: payload.origin_chain,
                            origin_nonce: payload.origin_nonce,
                            token_address: payload.token_address,
                            amount: payload.amount,
                            recipient: payload.recipient,
                            fee_recipient: payload.fee_recipient,
                            message: payload.message,
                        },
                    ),
                )
        }
```

**File:** starknet/src/omni_bridge.cairo (L309-314)
```text
            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }
```

**File:** near/omni-bridge/src/lib.rs (L2656-2673)
```rust
        if transfer_message.fee.native_fee.0 != 0 {
            let origin_chain = transfer_message.origin_transfer_id.as_ref().map_or_else(
                || transfer_message.get_origin_chain(),
                |origin_transfer_id| origin_transfer_id.origin_chain,
            );

            if origin_chain.is_utxo_chain() {
                env::panic_str(BridgeError::NativeFeeForUtxoChain.to_string().as_str())
            } else if origin_chain == ChainKind::Near {
                Promise::new(fee_recipient.clone())
                    .transfer(NearToken::from_yoctonear(transfer_message.fee.native_fee.0))
                    .detach();
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```

**File:** starknet/CLAUDE.md (L37-40)
```markdown
### Fee Handling
- Fees are deducted on NEAR side before signing
- `fin_transfer` receives net amount (post-fee)
- Optional native token fees in `init_transfer` (e.g., for gas)
```
