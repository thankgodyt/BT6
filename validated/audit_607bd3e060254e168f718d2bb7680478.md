### Title
Native Fee (STRK) Permanently Locked in Starknet Contract While Unbacked Wrapped STRK Is Minted on NEAR — (`starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract collects STRK tokens as `native_fee` from users during `init_transfer`, but provides no mechanism to withdraw or distribute those tokens. Simultaneously, the NEAR bridge mints wrapped STRK to relayers as fee payment via `fin_transfer_send_tokens_callback` / `send_fee_internal`. This creates an unbacked wrapped-STRK supply on NEAR: the locked STRK cannot be used to honour redemptions, so the wrapped-STRK peg is broken by the cumulative native fees paid.

### Finding Description

**Root cause — Starknet side (`starknet/src/omni_bridge.cairo`, lines 309–313):**

Every call to `init_transfer` with `native_fee > 0` pulls STRK from the caller into the contract:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

The entire `IOmniBridge` interface exposes no `withdraw`, `rescue`, or admin-transfer function for the accumulated STRK: [2](#0-1) 

There is no match in the contract for any sweep/recover pattern either.

**Root cause — NEAR side (`near/omni-bridge/src/lib.rs`, lines 1736–1743):**

When `fin_transfer_send_tokens_callback` processes a Starknet-originated transfer, it **mints** wrapped STRK to the fee recipient for every non-zero `native_fee`:

```rust
if transfer_message.fee.native_fee.0 > 0 {
    let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());
    ext_token::ext(native_token_id)
        .with_static_gas(MINT_TOKEN_GAS)
        .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
        .detach();
}
``` [3](#0-2) 

The same minting path is taken in `send_fee_internal` (used by `claim_fee`): [4](#0-3) 

`get_native_token_id` for `ChainKind::Strk` resolves to the hardcoded STRK token address `strk:0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`: [5](#0-4) 

**Net effect:**

| Side | What happens |
|---|---|
| Starknet | `native_fee` STRK locked in contract, irrecoverable |
| NEAR | Wrapped STRK minted to relayer — unbacked by any redeemable STRK |

Every Starknet→NEAR transfer that carries a `native_fee` inflates the wrapped-STRK supply on NEAR beyond what the Starknet contract can honour on redemption.

### Impact Explanation

This is a **balance manipulation / escrow mis-accounting** issue. The total wrapped STRK outstanding on NEAR equals (bridged STRK) + (cumulative native fees minted to relayers). The Starknet contract holds (bridged STRK) + (native fees) in custody, but the native-fee portion is permanently locked and cannot be released to back redemptions. Any holder of wrapped STRK on NEAR who attempts to bridge back to Starknet will find the contract short of redeemable STRK by exactly the sum of all historical native fees. This is a direct, permanent loss of bridged funds for wrapped-STRK holders.

### Likelihood Explanation

`init_transfer` is a public, permissionless function callable by any Starknet user. Relayers are economically incentivised to request `native_fee > 0` to cover gas costs. The condition is therefore triggered in normal protocol operation on every Starknet→NEAR transfer that includes a native fee, making this a near-certain, continuously accumulating loss.

### Recommendation

One of the following fixes should be applied:

1. **Add a withdrawal function** to the Starknet contract (admin-gated) that transfers accumulated STRK to a designated relayer treasury or bridges it back to NEAR, so the locked STRK can back the minted wrapped STRK.
2. **Do not mint wrapped STRK on NEAR** for Starknet-originated native fees; instead, pay relayers directly from the locked STRK on the Starknet side via a dedicated claim mechanism.
3. **Burn the native_fee STRK** on Starknet and correspondingly skip minting on NEAR, treating the native fee as a pure protocol fee with no cross-chain representation.

### Proof of Concept

1. Alice calls `init_transfer` on the Starknet `OmniBridge` with `native_fee = 1000 STRK`. The contract pulls 1000 STRK from Alice and locks it permanently.
2. A relayer submits the corresponding proof to the NEAR bridge via `fin_transfer`.
3. `fin_transfer_send_tokens_callback` calls `mint(relayer, 1000, None)` on the wrapped-STRK NEP-141 token — creating 1000 unbacked wrapped STRK on NEAR.
4. The relayer sells the 1000 wrapped STRK to Bob on NEAR.
5. Bob calls `ft_transfer_call` on NEAR to bridge his 1000 wrapped STRK back to Starknet. The NEAR bridge burns the wrapped STRK and signs a `fin_transfer` payload.
6. The Starknet `fin_transfer` attempts `IERC20.transfer(Bob, 1000)` from the contract's STRK balance. The contract holds the 1000 STRK from Alice's native fee, but that balance is indistinguishable from bridged STRK — it will be consumed, leaving the contract short for future legitimate redemptions. As native fees accumulate across many transfers, the Starknet contract's redeemable STRK balance is progressively drained relative to the outstanding wrapped-STRK supply on NEAR, eventually causing redemption failures for legitimate wrapped-STRK holders. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1690-1747)
```rust
    #[allow(clippy::needless_pass_by_value)]
    #[private]
    pub fn fin_transfer_send_tokens_callback(
        &mut self,
        #[serializer(borsh)] transfer_message: TransferMessage,
        #[serializer(borsh)] fee_recipient: &AccountId,
        #[serializer(borsh)] is_ft_transfer_call: bool,
        #[serializer(borsh)] storage_owner: &AccountId,
        #[serializer(borsh)] lock_actions: Vec<LockAction>,
    ) {
        let token = self.get_token_id(&transfer_message.token);

        if Self::is_refund_required(is_ft_transfer_call) {
            self.burn_tokens_if_needed(
                token.clone(),
                U128(
                    transfer_message
                        .amount_without_fee()
                        .near_expect(BridgeError::InvalidFee),
                ),
            );

            self.revert_lock_actions(&lock_actions);

            self.remove_fin_transfer(&transfer_message.get_transfer_id(), storage_owner);

            env::log_str(
                &OmniBridgeEvent::FailedFinTransferEvent { transfer_message }.to_log_string(),
            );
        } else {
            // Send fee to the fee recipient
            if transfer_message.fee.fee.0 > 0 {
                if self.is_deployed_token(&token) {
                    ext_token::ext(token)
                        .with_static_gas(MINT_TOKEN_GAS)
                        .mint(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                } else {
                    ext_token::ext(token)
                        .with_attached_deposit(ONE_YOCTO)
                        .with_static_gas(FT_TRANSFER_GAS)
                        .ft_transfer(fee_recipient.clone(), transfer_message.fee.fee, None)
                        .detach();
                }
            }

            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }

            env::log_str(&OmniBridgeEvent::FinTransferEvent { transfer_message }.to_log_string());
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L2668-2673)
```rust
            } else {
                ext_token::ext(self.get_native_token_id(origin_chain))
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```

**File:** near/omni-types/src/lib.rs (L944-948)
```rust
pub fn get_native_token_address(chain_kind: ChainKind) -> Result<OmniAddress, String> {
    match chain_kind {
        ChainKind::Strk => OmniAddress::from_str(
            "strk:0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
        ),
```
