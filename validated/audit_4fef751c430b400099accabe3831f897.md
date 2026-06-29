### Title
`OmniBridge.sol::initTransfer` Accepts Unregistered ERC20 Tokens, Permanently Locking User Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::initTransfer` locks any caller-supplied ERC20 token into the contract without verifying that the token is registered in the bridge (i.e., that `ethToNearToken[tokenAddress]` is non-empty). If the token has no corresponding NEAR-side registration, the NEAR `fin_transfer_callback` panics with `TokenDecimalsNotFound`, the cross-chain transfer is never finalized, and the locked tokens are permanently irrecoverable because no admin sweep or emergency-withdrawal function exists in the contract.

---

### Finding Description

`initTransfer` in `OmniBridge.sol` handles three ERC20 paths: [1](#0-0) 

```
customMinters[tokenAddress] != address(0)  → burn via custom minter
isBridgeToken[tokenAddress]                → burn bridge token
else                                       → safeTransferFrom(msg.sender, address(this), amount)
```

The `else` branch — which covers every ordinary ERC20 that is neither a bridge-deployed token nor a custom-minter token — performs no check that `ethToNearToken[tokenAddress]` is set. A token that has never had `logMetadata` called (or whose mapping was removed via `removeCustomToken`) passes silently through this branch and is locked in the contract. [2](#0-1) 

On the NEAR side, `fin_transfer_callback` immediately looks up the token's decimals: [3](#0-2) 

If the token was never registered, `token_decimals.get(&init_transfer.token)` returns `None` and the callback panics with `BridgeError::TokenDecimalsNotFound`. The EVM-side lock is never reversed — there is no refund path triggered by a failed NEAR callback, and the contract exposes no `sweep` or `emergencyWithdraw` function for arbitrary ERC20 tokens. [4](#0-3) 

The `initTransfer1155` path has the same gap: it locks any ERC1155 token without verifying the `multiTokens` mapping is populated. [5](#0-4) 

---

### Impact Explanation

Any user who calls `initTransfer` with an ERC20 token that is not registered in the bridge (no `ethToNearToken` entry, no `token_decimals` entry on NEAR) will have their tokens permanently locked in the EVM contract. There is no on-chain recovery path: the contract has no admin function to withdraw arbitrary ERC20 tokens, and the NEAR-side failure does not trigger any EVM-side refund. This constitutes a **permanent, irreversible loss of bridged funds** for the affected user.

---

### Likelihood Explanation

The entry point is fully public and requires no special role. Realistic triggering scenarios include:

- A user bridges a token that was recently de-listed (its `removeCustomToken` was called), not knowing it is no longer supported.
- A user calls `initTransfer` before calling `logMetadata` and waiting for the NEAR-side registration to complete.
- A user supplies a token address with a typo or confusion between two similarly named tokens.

No admin compromise or privileged access is required.

---

### Recommendation

Add a registration guard at the top of `initTransfer` (and `initTransfer1155`) before any token transfer occurs:

```solidity
// For ERC-20
require(
    tokenAddress == address(0) ||
    isBridgeToken[tokenAddress] ||
    customMinters[tokenAddress] != address(0) ||
    bytes(ethToNearToken[tokenAddress]).length > 0,
    "ERR_TOKEN_NOT_REGISTERED"
);
```

This mirrors the pattern used in `setMetadata`, which already guards on `isBridgeToken[nearToEthToken[token]]` before acting. [6](#0-5) 

---

### Proof of Concept

1. Deploy or obtain any ERC20 token `T` that has **not** been registered via `logMetadata` / `deployToken` (i.e., `ethToNearToken[T] == ""`).
2. Approve `OmniBridge` to spend `T`.
3. Call `OmniBridge.initTransfer(T, amount, 0, 0, "<valid-near-recipient>", "")`.
4. `safeTransferFrom` succeeds; `amount` of `T` is now held by `OmniBridge`. The `InitTransfer` event is emitted.
5. A relayer submits the proof to NEAR `fin_transfer`.
6. `fin_transfer_callback` panics: `token_decimals.get(&init_transfer.token)` returns `None` → `BridgeError::TokenDecimalsNotFound`.
7. No EVM-side refund is triggered. `T` tokens remain locked in `OmniBridge` forever with no recovery path. [7](#0-6) [2](#0-1)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L209-209)
```text
        require(isBridgeToken[nearToEthToken[token]], "ERR_NOT_BRIDGE_TOKEN");
```

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
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
