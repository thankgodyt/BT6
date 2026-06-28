### Title
ERC721 Token Deposited via ERC20 `initTransfer` Path Causes Permanent Fund Lock - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

`OmniBridge.initTransfer` accepts any token address and uses `SafeERC20.safeTransferFrom` to pull tokens. Because ERC721's `transferFrom(from, to, tokenId)` shares the same ABI selector as ERC20's `transferFrom(from, to, amount)`, an ERC721 token can be deposited via the ERC20 path. However, `finTransfer` attempts to release funds via `IERC20.safeTransfer(recipient, amount)`, which ERC721 does not implement, causing the withdrawal to permanently revert and locking the NFT in the bridge while leaving unbacked tokens minted on NEAR.

### Finding Description

`initTransfer` in `OmniBridge.sol` contains no token-type validation. It blindly calls `IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount)`: [1](#0-0) 

OpenZeppelin's `SafeERC20.safeTransferFrom` calls `token.transferFrom(from, to, value)` and treats a no-return-data success as valid. ERC721's `transferFrom(from, to, tokenId)` has the **identical 3-argument ABI signature** and does not return a bool, so `SafeERC20` accepts it without reverting. The ERC721 token is transferred into the bridge.

`logMetadata` is permissionless and calls `IERC20Metadata(tokenAddress).name()`, `.symbol()`, `.decimals()`: [2](#0-1) 

Many ERC721 contracts implement these metadata functions. An attacker calls `logMetadata(erc721Address)` first, causing NEAR to deploy a fungible token for the ERC721 address. Then `initTransfer(erc721Address, tokenId, 0, 0, "attacker.near", "")` is called, locking the NFT and triggering NEAR to mint `tokenId` units of the fungible token to the attacker.

When `finTransfer` is later called to release funds on the EVM side, the dispatch logic checks `multiTokens[payload.tokenAddress]` (empty, since no `logMetadata1155` was called), `customMinters`, and `isBridgeToken`, all of which are zero/false for a raw ERC721. It falls through to: [3](#0-2) 

ERC721 has no `transfer(address, uint256)` function. This call reverts unconditionally. The nonce is already marked used: [4](#0-3) 

The transfer is permanently finalized on-chain but the ERC721 can never be released. The NEAR-side fungible tokens are now unbacked.

### Impact Explanation

- The ERC721 NFT is permanently frozen inside the bridge contract with no recovery path.
- NEAR mints `tokenId` units of a fungible token that are unbacked by any redeemable asset on the EVM side.
- If the attacker sells those NEAR tokens, they extract value while the NFT remains locked — a direct theft/escrow mis-accounting impact.
- Any legitimate holder of the NEAR-side tokens who later attempts to bridge back will find `finTransfer` always reverts, permanently destroying their redemption rights.

### Likelihood Explanation

The attack is fully permissionless. `logMetadata` and `initTransfer` require no role or whitelist. The attacker only needs:
1. An ERC721 that exposes `name()`, `symbol()`, `decimals()` (common in ERC721 with metadata, e.g., OpenZeppelin's `ERC721URIStorage` or any token implementing `IERC20Metadata` alongside ERC721).
2. Ownership of at least one token ID.
3. Approval granted to the bridge.

No admin compromise, no oracle manipulation, and no front-running is required.

### Recommendation

Add an ERC165 interface check in `initTransfer` to reject tokens that advertise ERC721 (`0x80ac58cd`) or ERC1155 (`0xd9b67a26`) support:

```solidity
if (IERC165(tokenAddress).supportsInterface(0x80ac58cd) ||
    IERC165(tokenAddress).supportsInterface(0xd9b67a26)) {
    revert UnsupportedTokenType();
}
```

Alternatively, maintain a separate whitelist for ERC20 tokens distinct from ERC1155 tokens (analogous to the original report's recommendation to split the whitelist). The `multiTokens` mapping already separates ERC1155 handling; the same separation must be enforced at the deposit entry point.

### Proof of Concept

1. Deploy or obtain an ERC721 contract that also implements `name()`, `symbol()`, `decimals()`.
2. Call `bridge.logMetadata(erc721Address)` — succeeds, NEAR deploys a fungible token.
3. Approve the bridge: `erc721.approve(bridgeAddress, tokenId)`.
4. Call `bridge.initTransfer(erc721Address, tokenId, 0, 0, "attacker.near", "")`.
   - `SafeERC20.safeTransferFrom` resolves to ERC721's `transferFrom(attacker, bridge, tokenId)` — succeeds.
   - `InitTransfer` event emitted; NEAR mints `tokenId` fungible tokens to `attacker.near`.
5. Attacker transfers/sells the NEAR fungible tokens.
6. Any call to `bridge.finTransfer(sig, {tokenAddress: erc721Address, amount: tokenId, recipient: X, ...})`:
   - `multiTokens[erc721Address].tokenAddress == address(0)` → skip ERC1155 branch.
   - `customMinters[erc721Address] == address(0)` → skip custom minter branch.
   - `isBridgeToken[erc721Address] == false` → skip bridge token branch.
   - Falls to `IERC20(erc721Address).safeTransfer(X, tokenId)` → **reverts** (no such function on ERC721).
   - Nonce already consumed; ERC721 permanently locked. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L315-355)
```text
        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
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
```
