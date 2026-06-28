### Title
ETH `nativeFee` Permanently Locked in EVM Bridge Contracts — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

The `initTransfer` function in `OmniBridge.sol` is `payable` and accepts ETH from callers. For ERC20 token transfers, the caller sends `msg.value = nativeFee + extensionValue`. Only `extensionValue` is forwarded onward (to Wormhole in `OmniBridgeWormhole.sol`); the `nativeFee` portion of ETH remains in the contract. No sweep or withdrawal function exists for this accumulated ETH, so every `nativeFee` payment is permanently locked.

### Finding Description

In `OmniBridge.sol`, `initTransfer` computes:

```solidity
extensionValue = msg.value - nativeFee;   // ERC20 path
``` [1](#0-0) 

The `extensionValue` is passed to `initTransferExtension`, which in `OmniBridgeWormhole.sol` forwards it to Wormhole:

```solidity
_wormhole.publishMessage{value: value}(wormholeNonce, payload, _consistencyLevel);
``` [2](#0-1) 

The `nativeFee` ETH is never forwarded anywhere — it stays in the contract balance. On the NEAR side, the relayer is compensated by minting wrapped native tokens (e.g., wrapped ETH) via `get_native_token_id`:

```rust
ext_token::ext(self.get_native_token_id(origin_chain))
    .with_static_gas(MINT_TOKEN_GAS)
    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
    .detach();
``` [3](#0-2) 

This means the actual ETH `nativeFee` is never consumed or sent to the relayer on EVM — it accumulates in the EVM contract indefinitely. No `sweepETH`, `rescueETH`, or equivalent admin function is present in the reviewed production contract code.

### Impact Explanation

Every user who pays a non-zero `nativeFee` in ETH when calling `initTransfer` permanently loses that ETH to the contract. Over time, across all bridge users on Ethereum, Arbitrum, Base, Polygon, and BNB (all chains using `OmniBridgeWormhole`), this accumulates into a significant sum of locked ETH with no protocol-controlled recovery path. This is a direct, permanent loss of user funds.

### Likelihood Explanation

The `nativeFee` is a standard, documented parameter of `initTransfer` actively used by bridge users to incentivize relayers. Any user paying a non-zero `nativeFee` triggers this loss. The README explicitly documents this fee mechanism: [4](#0-3) 

The path is reachable by any unprivileged bridge user with no special preconditions.

### Recommendation

Add an admin-controlled ETH sweep function to `OmniBridge.sol` (analogous to the fix applied in the referenced Compound commit), for example:

```solidity
function sweepETH(address payable recipient) external onlyAdmin {
    recipient.transfer(address(this).balance);
}
```

Alternatively, refund the `nativeFee` ETH to `msg.sender` within `initTransfer` if it is not forwarded to Wormhole, or forward it explicitly to a designated fee collector on EVM.

### Proof of Concept

1. User calls `initTransfer(erc20Token, 1000, 0, 1e17, "near:recipient", "")` with `msg.value = 1e17` (0.1 ETH as `nativeFee`).
2. `extensionValue = 1e17 - 1e17 = 0` → Wormhole receives 0 ETH.
3. The 0.1 ETH `nativeFee` remains in `OmniBridgeWormhole`'s balance.
4. The NEAR relayer is minted 0.1 wrapped-ETH on NEAR via `mint(fee_recipient, native_fee)`.
5. The 0.1 ETH in the EVM contract is unrecoverable — no sweep function exists.
6. Repeated across all bridge users, the locked ETH balance grows without bound. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
    }
```

**File:** near/omni-bridge/src/lib.rs (L1669-1672)
```rust

    pub fn get_mpc_account(&self) -> AccountId {
        self.mpc_signer.clone()
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

**File:** README.md (L184-198)
```markdown
### EVM API
```solidity
// 1. Approve tokens
function approve(address spender, uint256 amount)

// 2. Initiate transfer
function initTransfer(
    address tokenAddress,
    uint128 amount,
    uint128 fee,
    uint128 nativeFee,
    string calldata recipient,
    string calldata message
) payable external
```
```
