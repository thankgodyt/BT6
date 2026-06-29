### Title
Unregistered Token Accepted in `init_transfer` Causes Permanent Fund Freezing — (`starknet/src/omni_bridge.cairo`, `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

The Starknet and EVM `init_transfer` functions accept any arbitrary ERC-20 token address without verifying that the token is registered in the bridge's token mappings. Tokens locked or burned on the source chain cannot be recovered because the NEAR side panics when it cannot find the token's decimal metadata, and no refund/cancel mechanism exists on the source chain.

### Finding Description

**Starknet (`starknet/src/omni_bridge.cairo`, `init_transfer`, lines 281–331):**

The function checks `is_bridge_token(token_address)` only to decide whether to burn or lock the token. It does **not** require the token to be registered in `starknet_to_near_token` / `near_to_starknet_token`. Any arbitrary ERC-20 token passes the fee/amount checks and is accepted:

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
// No check: starknet_to_near_token[token_address] must be non-empty
self.emit(Event::InitTransfer(...))
``` [1](#0-0) 

**EVM (`evm/src/omni-bridge/contracts/OmniBridge.sol`, `initTransfer`, lines 373–437):**

Similarly, the EVM bridge accepts any token address. For tokens that are neither a `customMinter` nor an `isBridgeToken`, it simply does `safeTransferFrom` to lock the token, with no check that `ethToNearToken[tokenAddress]` is set:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
}
emit BridgeTypes.InitTransfer(...);
``` [2](#0-1) 

**NEAR side rejection (`near/omni-bridge/src/lib.rs`, `fin_transfer_callback`, lines 715–718):**

When the relayer submits the proof of the source-chain event to NEAR, `fin_transfer_callback` immediately panics if the token is not registered:

```rust
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
``` [3](#0-2) 

Because the panic occurs before `add_fin_transfer` is called, the transfer is never marked as finalized in `finalised_transfers`. The source-chain tokens remain locked in the bridge contract with no recovery path. [4](#0-3) 

Neither the Starknet contract nor the EVM contract exposes a `cancel_transfer`, `refund`, or `rescue` function for locked tokens. [5](#0-4) 

### Impact Explanation

Any user who calls `init_transfer` (Starknet) or `initTransfer` (EVM) with a token that has not been registered via `deploy_token` / `bind_token` on the NEAR side will have their tokens permanently frozen in the source-chain bridge contract. The NEAR side will always reject the proof, and there is no on-chain mechanism to recover the locked funds. This constitutes permanent loss of bridged funds.

### Likelihood Explanation

The entry path is fully unprivileged — any token holder can call `init_transfer` / `initTransfer` directly. A user may accidentally use a token that was not yet registered (e.g., a newly deployed token, a token whose `log_metadata` + `deploy_token` flow was not yet completed, or a token on a chain where the bridge is partially deployed). No special role or leaked key is required.

### Recommendation

Add an explicit registration check at the start of `init_transfer` (Starknet) and `initTransfer` (EVM):

**Starknet:**
```cairo
let token_id_hash = compute_keccak_byte_array(@token_address_to_near_id(token_address));
let near_token = self.starknet_to_near_token.read(token_address);
assert(near_token.len() > 0, 'ERR_TOKEN_NOT_REGISTERED');
```

**EVM:**
```solidity
require(bytes(ethToNearToken[tokenAddress]).length > 0 || tokenAddress == address(0), "ERR_TOKEN_NOT_REGISTERED");
``` [6](#0-5) [7](#0-6) 

### Proof of Concept

1. Deploy any ERC-20 token on Starknet (or EVM) that has **not** been registered in the NEAR bridge via `deploy_token` or `bind_token`.
2. Approve the Starknet (or EVM) bridge contract to spend the token.
3. Call `init_transfer(unregistered_token, amount, 0, 0, "victim.near", "")`.
4. The token is transferred from the caller to the bridge contract and an `InitTransfer` event is emitted.
5. A relayer submits the proof to the NEAR `fin_transfer` endpoint.
6. `fin_transfer_callback` panics at `token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)`.
7. The NEAR transaction reverts; the source-chain tokens remain permanently locked with no recovery path. [8](#0-7) [9](#0-8)

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

**File:** starknet/src/omni_bridge.cairo (L113-116)
```text
        completed_transfers: Map<u64, felt252>,
        starknet_to_near_token: Map<ContractAddress, ByteArray>,
        // Can't use ByteArray as a key. Using hash instead
        near_to_starknet_token: Map<u256, ContractAddress>,
```

**File:** starknet/src/omni_bridge.cairo (L290-331)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L36-38)
```text
    mapping(address => string) public ethToNearToken;
    mapping(string => address) public nearToEthToken;
    mapping(address => bool) public isBridgeToken;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-412)
```text
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
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

**File:** near/omni-bridge/src/lib.rs (L1875-1877)
```rust
        let mut required_balance = self.add_fin_transfer(&transfer_message.get_transfer_id());

        let token = self.get_token_id(&transfer_message.token);
```
