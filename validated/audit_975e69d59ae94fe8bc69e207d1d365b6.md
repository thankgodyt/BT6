### Title
ERC-1155 Tokens Permanently Locked When `initTransfer1155` Is Called Without Prior `logMetadata1155` Registration — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`initTransfer1155` accepts and locks ERC-1155 tokens into the bridge escrow without verifying that the corresponding `logMetadata1155` registration has been performed. Because the NEAR-side `fin_transfer_callback` panics with `ERR_TOKEN_DECIMALS_NOT_FOUND` when the token is unknown, the locked ERC-1155 tokens have no automatic recovery path and can be permanently frozen.

### Finding Description

`OmniBridge.initTransfer1155` computes a deterministic proxy address for the `(tokenAddress, tokenId)` pair, pulls the ERC-1155 tokens from the caller, and emits `InitTransfer` — all without checking whether `multiTokens[deterministicToken]` has been populated by a prior `logMetadata1155` call. [1](#0-0) 

`logMetadata1155` is the only function that writes to `multiTokens[deterministicToken]`: [2](#0-1) 

When a relayer subsequently submits the EVM proof to the NEAR bridge, `fin_transfer_callback` attempts to look up token decimals for the unregistered token: [3](#0-2) 

This call panics with `BridgeError::TokenDecimalsNotFound`, reverting the NEAR transaction. The EVM-side ERC-1155 tokens remain locked in the bridge with no on-chain refund or rescue mechanism. The existing test suite even demonstrates that `initTransfer1155` succeeds without a prior `logMetadata1155` call: [4](#0-3) 

### Impact Explanation

ERC-1155 tokens transferred via `initTransfer1155` without a preceding `logMetadata1155` are locked in the EVM bridge contract. The NEAR-side processing fails unconditionally, and there is no EVM-side refund path. If the EVM light-client prover marks the receipt as consumed on the first failed attempt, the proof cannot be resubmitted even after the token is later registered, making the freeze permanent. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation

`logMetadata1155` and `initTransfer1155` are separate, permissionless, externally callable functions with no enforced ordering. A user unfamiliar with the two-step registration flow — or a front-end that omits the registration step — will trigger this condition. The existing test suite itself calls `initTransfer1155` without `logMetadata1155` (line 193 of `OmniBridge1155.test.ts`), confirming the path is reachable in practice.

### Recommendation

Add a guard at the top of `initTransfer1155` that reverts if `multiTokens[deterministicToken].tokenAddress == address(0)`:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
if (multiTokens[deterministicToken].tokenAddress == address(0)) {
    revert ERC1155NotRegistered();
}
```

This mirrors the pattern used in `logMetadata1155` itself, which already checks and enforces mapping consistency. [5](#0-4) 

### Proof of Concept

1. Deploy `OmniBridge` and a standard ERC-1155 contract.
2. Mint tokens to `user` and approve the bridge.
3. Call `initTransfer1155(erc1155, tokenId, amount, 0, 0, "victim.near", "")` — **without** calling `logMetadata1155` first. The call succeeds; tokens are now in the bridge.
4. A relayer submits the EVM receipt proof to the NEAR bridge via `fin_transfer`.
5. NEAR's `fin_transfer_callback` panics at `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)`.
6. The NEAR transaction reverts; the ERC-1155 tokens remain locked in the EVM bridge with no recovery path. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-270)
```text
    function logMetadata1155(
        address tokenAddress,
        uint256 tokenId
    ) external payable {
        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        MultiTokenInfo storage multiToken = multiTokens[deterministicToken];

        if (multiToken.tokenAddress == address(0)) {
            multiToken.tokenAddress = tokenAddress;
            multiToken.tokenId = tokenId;
        } else {
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
        }

        logMetadataExtension(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
        );

        emit BridgeTypes.LogMetadata(
            deterministicToken,
            Strings.toHexString(tokenAddress),
            "",
            0
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

**File:** evm/tests/OmniBridge1155.test.ts (L191-194)
```typescript
    await bridge
      .connect(user)
      .initTransfer1155(await erc1155.getAddress(), tokenId, 1, 0, 0, "receiver.near", "")
    expect(await erc1155.balanceOf(bridgeAddress, tokenId)).to.equal(1n)
```
