### Title
STRK Native Fees Collected in `init_transfer` Are Permanently Locked in the Starknet OmniBridge — (`starknet/src/omni_bridge.cairo`)

### Summary
The Starknet `OmniBridge` contract pulls STRK tokens from users as `native_fee` during `init_transfer` and holds them in the contract itself. No function exists anywhere in the contract to withdraw or forward these accumulated STRK fees, causing them to be permanently frozen.

### Finding Description
In `init_transfer`, when `native_fee > 0`, the contract executes an ERC-20 `transfer_from` that moves STRK tokens from the caller directly into `get_contract_address()` — the bridge contract itself:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

The entire public `IOmniBridge` interface is: [2](#0-1) 

None of these functions — `log_metadata`, `deploy_token`, `fin_transfer`, `init_transfer`, `upgrade_token`, `set_pause_flags`, `pause_all`, `get_token_address`, `is_bridge_token`, `is_transfer_finalised` — allow withdrawal of the accumulated STRK balance. The `upgrade` function (via `UpgradeableImpl`) only upgrades the class hash and does not transfer tokens. There is no `rescue`, `withdraw_fees`, or equivalent admin function anywhere in the contract. [3](#0-2) 

By contrast, on the NEAR side, native fees paid by users are held in the user's storage balance and are explicitly forwarded to the relayer's account during `fin_transfer_send_tokens_callback` via a `mint` call to the native token contract — they are never held permanently in the bridge contract. [4](#0-3) 

On Starknet, the STRK native fee has no analogous forwarding path — it simply accumulates in the bridge contract with no exit.

### Impact Explanation
Every `init_transfer` call with `native_fee > 0` permanently locks STRK tokens in the Starknet OmniBridge contract. Relayers who are supposed to receive these fees as incentives for processing cross-chain transfers from Starknet can never claim them. This is permanent freezing of user-paid fee funds and constitutes fee mis-accounting across the Starknet leg of the bridge.

### Likelihood Explanation
High. The `native_fee` parameter is a documented, first-class feature of the bridge protocol (used on every supported chain). Any user who pays a non-zero `native_fee` on Starknet triggers the vulnerable code path. No special conditions or attacker privileges are required — this is a standard bridge usage path reachable by any unprivileged user. [5](#0-4) 

### Recommendation
Add a privileged withdrawal function restricted to `DEFAULT_ADMIN_ROLE` (or a dedicated fee-collector role) that transfers accumulated STRK tokens from the contract to a designated recipient:

```cairo
fn withdraw_native_fees(ref self: ContractState, recipient: ContractAddress, amount: u128) {
    self.accesscontrol.assert_only_role(DEFAULT_ADMIN_ROLE);
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer(recipient, amount.into());
    assert(success, 'ERR_FEE_WITHDRAWAL_FAILED');
}
```

Alternatively, forward the `native_fee` directly to a relayer/fee-recipient address at the time of `init_transfer`, rather than holding it in the contract.

### Proof of Concept
1. User approves the Starknet OmniBridge to spend 1000 STRK.
2. User calls `init_transfer(token_address, amount=500, fee=10, native_fee=1000, recipient, message)`.
3. Contract executes `transfer_from(user, bridge_contract, 1000)` — 1000 STRK moves into the bridge.
4. The `InitTransfer` event is emitted; the NEAR side processes the transfer and the relayer expects to receive 1000 STRK as their native fee incentive.
5. No function exists on the Starknet contract to withdraw or forward the 1000 STRK.
6. Repeated across all users: all STRK native fees accumulate permanently in the bridge contract and are irrecoverable. [6](#0-5)

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

**File:** starknet/src/omni_bridge.cairo (L100-120)
```text
    // Used nonces
    #[storage]
    struct Storage {
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        pause_flags: u8,
        bridge_token_class_hash: ClassHash,
        current_origin_nonce: u64,
        // Bitmap: slot = nonce / 251, bit = nonce % 251
        completed_transfers: Map<u64, felt252>,
        starknet_to_near_token: Map<ContractAddress, ByteArray>,
        // Can't use ByteArray as a key. Using hash instead
        near_to_starknet_token: Map<u256, ContractAddress>,
        omni_bridge_chain_id: u8,
        omni_bridge_derived_address: EthAddress,
        strk_token_address: ContractAddress,
    }
```

**File:** starknet/src/omni_bridge.cairo (L281-314)
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
```

**File:** starknet/src/omni_bridge.cairo (L389-395)
```text
    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.accesscontrol.assert_only_role(DEFAULT_ADMIN_ROLE);
            self.upgradeable.upgrade(new_class_hash);
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L1736-1743)
```rust
            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```
