### Title
Starknet Native Fees Permanently Locked in OmniBridge Contract With No Withdrawal Mechanism - (`starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract collects STRK native fees from users during `init_transfer` by transferring them to itself (`get_contract_address()`), but the contract exposes no function to withdraw or distribute these accumulated STRK tokens. The fees are permanently locked until a contract upgrade is performed.

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function accepts an optional `native_fee` parameter. When non-zero, it pulls STRK tokens from the caller directly into the bridge contract:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
```

The entire `IOmniBridge` interface exposes only: `log_metadata`, `deploy_token`, `fin_transfer`, `init_transfer`, `upgrade_token`, `set_pause_flags`, `pause_all`, and three view functions. None of these allow withdrawing the accumulated STRK native fees. The `IUpgradeable` implementation only upgrades the contract class hash — it does not transfer ERC-20 balances.

On the NEAR side, when a Starknet→NEAR transfer is finalized, the relayer is compensated by **minting** wrapped STRK tokens (`native_token_id` mint call in `fin_transfer_send_tokens_callback`). The actual STRK deposited on Starknet is never released — it accumulates in the contract indefinitely.

### Impact Explanation

Every `init_transfer` call with `native_fee > 0` permanently locks real STRK tokens in the Starknet bridge contract. These tokens cannot be recovered by relayers, the protocol, or users. The protocol simultaneously mints wrapped STRK on NEAR to compensate relayers, creating an ever-growing pool of locked STRK on Starknet with no redemption path. This constitutes permanent freezing of user-paid bridged funds on Starknet.

### Likelihood Explanation

The `native_fee` parameter is a standard, documented feature of the bridge's transfer initiation API (described in `README.md` as one of the two supported fee payment methods). Any user initiating a Starknet→NEAR transfer who pays a native fee triggers this path. The likelihood is high because native fee payment is a normal, expected operation.

### Recommendation

Add an admin-gated withdrawal function to the `IOmniBridge` interface and its implementation that allows the `DEFAULT_ADMIN_ROLE` to transfer accumulated STRK native fees to a designated treasury or fee distributor address:

```cairo
fn withdraw_native_fees(ref self: TContractState, recipient: ContractAddress, amount: u128);
```

This mirrors the `withdrawProfits()` pattern used in `RageDnDepository` on the UXD protocol side.

### Proof of Concept

1. User calls `init_transfer(token, 1000, 10, 500_000_000_000_000_000, "near:recipient", "")` on the Starknet bridge, paying 0.5 STRK as `native_fee`.
2. The contract executes `transfer_from(caller, get_contract_address(), 500_000_000_000_000_000)` — STRK is now held by the bridge contract.
3. The relayer submits the proof on NEAR; `fin_transfer_send_tokens_callback` mints wrapped STRK to the relayer on NEAR.
4. The 0.5 STRK on Starknet remains in the bridge contract. No function in `IOmniBridge` can move it out.
5. Repeat for every transfer with `native_fee > 0`. The locked STRK balance grows monotonically with no withdrawal path.

---

**Root cause:** [1](#0-0) 

**No withdrawal function in the interface:** [2](#0-1) 

**NEAR side mints wrapped STRK instead of releasing locked STRK:** [3](#0-2)

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

**File:** starknet/src/omni_bridge.cairo (L309-314)
```text
            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
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
