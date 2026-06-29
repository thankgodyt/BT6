### Title
Native Fee (STRK) Permanently Stuck in Starknet Bridge Contract — (`starknet/src/omni_bridge.cairo`)

---

### Summary

The Starknet `OmniBridge` contract collects `native_fee` (STRK tokens) from users during `init_transfer`, transferring them into the bridge contract itself. However, the contract exposes no function to withdraw or distribute these accumulated STRK fees to relayers or any other recipient. Every `init_transfer` call with a non-zero `native_fee` permanently locks STRK tokens in the contract.

---

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function accepts an optional `native_fee` parameter denominated in STRK tokens. When non-zero, the fee is pulled from the caller and deposited into the bridge contract address: [1](#0-0) 

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
```

The entire public interface of the contract is: [2](#0-1) 

None of the nine exposed functions — `log_metadata`, `deploy_token`, `fin_transfer`, `init_transfer`, `upgrade_token`, `set_pause_flags`, `pause_all`, `get_token_address`, `is_bridge_token`, `is_transfer_finalised` — provide any mechanism to withdraw or forward the accumulated STRK balance. There is no `withdraw_fees`, `rescue`, or admin sweep function anywhere in the contract.

The `fin_transfer` path on Starknet only mints/unlocks the bridged token amount to the recipient; it does not touch the STRK fee balance: [3](#0-2) 

The Starknet CLAUDE documentation confirms the design intent: native fees are paid on Starknet to compensate relayers for gas, but the fee distribution mechanism is absent from the contract: [4](#0-3) 

---

### Impact Explanation

Every `init_transfer` call with `native_fee > 0` permanently locks STRK tokens inside the bridge contract. Over time, the accumulated STRK balance grows and becomes unrecoverable. Relayers receive no STRK compensation for their Starknet-side gas costs despite users paying for it. This is a direct fee mis-accounting issue: user funds are collected but never distributed, constituting a permanent loss of bridged-fee value for the protocol and its relayers.

---

### Likelihood Explanation

`init_transfer` is a fully public, unpermissioned function callable by any bridge user. Any user who sets `native_fee > 0` (which is the normal operating mode for incentivizing relayers) contributes to the stuck balance. This will occur on every normal transfer that includes a native fee, making it a near-certain accumulation issue in production.

---

### Recommendation

Add an admin-restricted function to withdraw accumulated STRK fees from the contract and forward them to a designated fee recipient or relayer treasury. For example:

```cairo
fn withdraw_native_fees(ref self: ContractState, recipient: ContractAddress, amount: u128) {
    self.accesscontrol.assert_only_role(DEFAULT_ADMIN_ROLE);
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer(recipient, amount.into());
    assert(success, 'ERR_FEE_WITHDRAWAL_FAILED');
}
```

Alternatively, distribute the `native_fee` directly to the relayer/fee recipient within the `init_transfer` execution flow rather than holding it in the contract.

---

### Proof of Concept

1. User calls `init_transfer` on the Starknet bridge with `native_fee = 1_000_000` (1 STRK).
2. The contract executes `transfer_from(caller, get_contract_address(), 1_000_000)` — STRK is now held by the bridge.
3. The `InitTransfer` event is emitted; a relayer picks it up and submits proof to NEAR.
4. On NEAR, `fin_transfer_send_tokens_callback` mints/transfers the token fee to the relayer — but the STRK on Starknet is never touched.
5. After 1,000 such transfers, 1,000 STRK are permanently locked in the Starknet bridge contract with no recovery path. [5](#0-4)

### Citations

**File:** starknet/src/omni_bridge.cairo (L9-32)
```text
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

**File:** starknet/src/omni_bridge.cairo (L281-331)
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

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
        }
```

**File:** starknet/CLAUDE.md (L37-40)
```markdown
### Fee Handling
- Fees are deducted on NEAR side before signing
- `fin_transfer` receives net amount (post-fee)
- Optional native token fees in `init_transfer` (e.g., for gas)
```
