### Title
Accumulated STRK Native Fees in Starknet Bridge Are Permanently Frozen — No Withdrawal Mechanism Exists - (File: `starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract collects `native_fee` STRK tokens from users during every `init_transfer` call and holds them in the contract. However, the contract exposes no function — admin or otherwise — to withdraw or distribute these accumulated STRK tokens. Every STRK native fee paid by any bridge user is permanently frozen in the contract.

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function accepts an optional `native_fee` parameter. When non-zero, it pulls STRK tokens from the caller directly into the contract address:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

The entire public interface of the contract is:

```cairo
fn log_metadata(...)
fn deploy_token(...)
fn fin_transfer(...)
fn init_transfer(...)
fn upgrade_token(...)
fn set_pause_flags(...)
fn pause_all(...)
fn get_token_address(...)
fn is_bridge_token(...)
fn is_transfer_finalised(...)
``` [2](#0-1) 

None of these functions withdraw ERC20 tokens from the contract. There is no `rescue`, `withdraw`, `sweep`, or admin token-recovery function anywhere in the contract. The STRK tokens transferred in via `native_fee` have no exit path.

### Impact Explanation

Every `init_transfer` call with `native_fee > 0` permanently locks STRK tokens inside the Starknet bridge contract. These fees are intended to compensate relayers for gas costs on the destination chain, but instead accumulate irrecoverably. The total frozen amount grows with every bridging operation that includes a native fee. This is a permanent, irreversible loss of protocol fee revenue and user-paid STRK tokens, matching the "permanent freezing of bridged funds" impact class.

### Likelihood Explanation

The `native_fee` parameter is a documented, user-facing feature of the bridge. The Starknet CLAUDE.md explicitly states: *"Optional native token fees in `init_transfer` (e.g., for gas)"*. [3](#0-2)  Any ordinary bridge user who sets `native_fee > 0` when calling `init_transfer` triggers the accumulation. No special role or privilege is required. The likelihood is high because native fees are a core incentive mechanism for relayers.

### Recommendation

Add an admin-only function to withdraw accumulated STRK (and any other ERC20) tokens from the contract:

```cairo
fn withdraw_fees(
    ref self: ContractState,
    token: ContractAddress,
    recipient: ContractAddress,
    amount: u128,
) {
    self.accesscontrol.assert_only_role(DEFAULT_ADMIN_ROLE);
    let success = IERC20Dispatcher { contract_address: token }
        .transfer(recipient, amount.into());
    assert(success, 'ERR_WITHDRAW_FAILED');
}
```

This mirrors the fix recommended in H-04: make the accumulated balance accessible through a privileged withdrawal path.

### Proof of Concept

1. Alice calls `init_transfer(token_address, 1000, 50, 100_000_000_000_000_000, "near:bob.near", "")` on the Starknet bridge, paying 0.1 STRK as `native_fee`.
2. The contract executes `transfer_from(Alice, get_contract_address(), 100_000_000_000_000_000)` — 0.1 STRK is now held by the bridge contract. [1](#0-0) 
3. The relayer completes the transfer on NEAR. The STRK fee is never forwarded to the relayer.
4. An admin inspects the contract's STRK balance and finds it non-zero, but there is no function in `IOmniBridge` to recover it. [2](#0-1) 
5. After N bridge operations with `native_fee > 0`, N × native_fee STRK is permanently frozen. There is no code path that ever calls `transfer` or `transfer_from` outward for the accumulated STRK balance.

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

**File:** starknet/src/omni_bridge.cairo (L309-314)
```text
            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }
```

**File:** starknet/CLAUDE.md (L37-40)
```markdown
### Fee Handling
- Fees are deducted on NEAR side before signing
- `fin_transfer` receives net amount (post-fee)
- Optional native token fees in `init_transfer` (e.g., for gas)
```
