### Title
ERC-721 Tokens Can Be Permanently Locked in OmniBridge via `initTransfer` — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` accepts any `tokenAddress` without validating that it is an ERC-20 token. Because OpenZeppelin's `SafeERC20.safeTransferFrom` encodes a call to `transferFrom(address,address,uint256)`, and ERC-721 exposes exactly that function signature, an ERC-721 token can be pulled into the bridge. However, the release path (`finTransfer`) calls `IERC20.safeTransfer` which encodes `transfer(address,uint256)` — a function ERC-721 does not implement — causing the release to revert and the NFT to be permanently locked.

### Finding Description

`initTransfer` in `OmniBridge.sol` handles native ERC-20 tokens with:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
``` [1](#0-0) 

`SafeERC20.safeTransferFrom` low-level-encodes `transferFrom(address from, address to, uint256 value)`. The ERC-721 standard exposes an identical function selector: `transferFrom(address from, address to, uint256 tokenId)`. OpenZeppelin's `_callOptionalReturn` also accepts an empty return value (ERC-721's `transferFrom` returns nothing), so the call succeeds and the NFT is deposited into the bridge.

There is no token-type guard anywhere in `initTransfer` — no `supportsInterface` check, no `decimals()` call, no registry lookup: [2](#0-1) 

The `logMetadata` function does call `IERC20Metadata(tokenAddress).decimals()` (which would revert for a standard ERC-721), but `logMetadata` is entirely optional and is never called or checked inside `initTransfer`: [3](#0-2) 

The `SECURITY.md` explicitly confirms `logMetadata` is permissionless and not a prerequisite: [4](#0-3) 

On the release side, `finTransfer` falls through to the ERC-20 path for any token that is not native ETH, not ERC-1155, not a custom minter, and not a bridge token:

```solidity
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
``` [5](#0-4) 

`safeTransfer` encodes `transfer(address,uint256)`. ERC-721 does not implement `transfer`, so this call reverts. The NFT is now permanently locked — there is no admin recovery path for arbitrary stuck tokens.

### Impact Explanation

An ERC-721 token whose `tokenId` fits in `uint128` and is `> 0` (to satisfy `fee < amount` with `fee = 0`) can be irreversibly locked in the `OmniBridge` contract. The token cannot be released via `finTransfer` (reverts), and there is no sweep or rescue function. This constitutes **permanent freezing of bridged funds**.

### Likelihood Explanation

The `initTransfer` function is fully permissionless and publicly callable. A user who mistakenly (or experimentally) passes an ERC-721 contract address as `tokenAddress` and a valid `tokenId` as `amount` will lose their NFT with no recourse. The function signature gives no indication that ERC-721 tokens are unsupported. The risk is realistic for any user who attempts to bridge an NFT through the generic ERC-20 path.

### Recommendation

Add a token-type guard in `initTransfer`. The simplest approach — consistent with the Linea report's suggestion — is to require that `decimals()` succeeds and returns a non-zero value, or to call `IERC165(tokenAddress).supportsInterface(type(IERC721).interfaceId)` and revert if it returns `true`. Alternatively, require that the token has been previously registered via `logMetadata` (i.e., enforce a whitelist).

### Proof of Concept

1. Attacker owns ERC-721 token at `nftAddress` with `tokenId = 1`.
2. Attacker calls `nftAddress.approve(omniBridgeAddress, 1)`.
3. Attacker calls `omniBridge.initTransfer(nftAddress, 1, 0, 0, "attacker.near", "")`.
4. Inside `initTransfer`: `IERC20(nftAddress).safeTransferFrom(attacker, bridge, 1)` → resolves to ERC-721's `transferFrom(attacker, bridge, 1)` → succeeds. NFT is now held by the bridge. `InitTransfer` event is emitted.
5. NEAR-side relayer sees the event but the token is not registered on NEAR; no valid `finTransfer` payload can be produced.
6. Even if a `finTransfer` were attempted on the EVM side with `tokenAddress = nftAddress`, `IERC20(nftAddress).safeTransfer(recipient, 1)` → encodes `transfer(recipient, 1)` → ERC-721 has no `transfer` → reverts.
7. NFT is permanently locked in `OmniBridge` with no recovery path. [6](#0-5)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
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

**File:** evm/SECURITY.md (L8-8)
```markdown
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
