### Title
ERC721/ERC20 `transferFrom` Selector Collision in `initTransfer()` Permanently Freezes NFTs in Bridge — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer()` casts any caller-supplied `tokenAddress` directly to `IERC20` and calls `safeTransferFrom`. Because `ERC721.transferFrom(address,address,uint256)` and `ERC20.transferFrom(address,address,uint256)` share the identical 4-byte selector `0x23b872dd`, an ERC721 token is silently accepted as if it were an ERC20. The NFT is locked in the bridge permanently because `finTransfer()` later calls `IERC20.safeTransfer()` (selector `0xa9059cbb`), a function that does not exist on ERC721, causing every redemption attempt to revert.

### Finding Description

`initTransfer()` contains no token-type validation. Its "else" branch unconditionally treats the caller-supplied address as an ERC20:

```solidity
// OmniBridge.sol lines 406-412
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount          // treated as tokenId by ERC721
    );
}
``` [1](#0-0) 

OpenZeppelin's `SafeERC20.safeTransferFrom` performs a low-level call to selector `0x23b872dd`. ERC721's `transferFrom` carries the same selector and returns no data (void). `SafeERC20` treats an empty return as success, so the call completes without reverting and the NFT is deposited into the bridge.

The companion `logMetadata()` function is also permissionless and performs no token-type check:

```solidity
// OmniBridge.sol lines 224-232
function logMetadata(address tokenAddress) external payable {
    string memory name = IERC20Metadata(tokenAddress).name();
    string memory symbol = IERC20Metadata(tokenAddress).symbol();
    uint8 decimals = IERC20Metadata(tokenAddress).decimals();
    logMetadataExtension(tokenAddress, name, symbol, decimals);
    emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
}
``` [2](#0-1) 

Many ERC721 contracts implement `name()`, `symbol()`, and `decimals()`, so `logMetadata` succeeds for them. The emitted `LogMetadata` event is picked up by the bridge relayer, which submits proof to NEAR and causes NEAR to deploy a bridged NEP-141 token mapped to the ERC721 address.

Once that mapping exists, the NEAR side's `fin_transfer` will mint NEP-141 tokens to the attacker when it receives proof of the `InitTransfer` event. The minted amount equals `tokenId` (the value passed as `amount`).

On the return path, `finTransfer()` falls through to:

```solidity
// OmniBridge.sol lines 350-355
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
``` [3](#0-2) 

`safeTransfer` calls `transfer(address,uint256)` (selector `0xa9059cbb`). ERC721 has no such function. Every `finTransfer` call for this token reverts, making the NFT irrecoverable.

### Impact Explanation

Two concrete harms result:

1. **Permanent freezing of the NFT.** The NFT is transferred into the bridge via the selector collision and can never be transferred out because `finTransfer` always reverts for ERC721 addresses. This matches the "permanent freezing of bridged funds" critical impact category.

2. **Unauthorized minting of unbacked NEP-141 tokens on NEAR.** After `logMetadata` registers the ERC721 on NEAR, the NEAR side mints real NEP-141 tokens to the attacker in exchange for the NFT. These tokens can be transferred or sold on NEAR, but they can never be redeemed for the underlying asset. This matches the "unauthorized minting" critical impact category.

### Likelihood Explanation

The attack is fully permissionless. `logMetadata` requires no role and no signature. `initTransfer` requires only that the caller holds and has approved the NFT. Any ERC721 that exposes `name()`, `symbol()`, and `decimals()` (a common pattern, e.g., OpenZeppelin's `ERC721` combined with `ERC721Metadata`) is a viable target. The bridge relayer processes `LogMetadata` events automatically. No admin compromise, no key leak, and no threshold-signature bypass is required.

### Recommendation

1. **Add an ERC-165 interface check** in `initTransfer` and `logMetadata` to reject addresses that advertise `IERC721` (`0x80ac58cd`) or `IERC1155` (`0xd9b67a26`) support.
2. **Maintain a token allowlist** (similar to the `isBridgeToken` / `customMinters` pattern already used) and require tokens to be explicitly registered before `initTransfer` accepts them.
3. **Alternatively**, check that `IERC165(tokenAddress).supportsInterface(type(IERC20).interfaceId)` returns `true` before proceeding, though note that not all ERC20s implement ERC-165.

### Proof of Concept

1. Attacker holds ERC721 token at address `nft` with `tokenId = T`. The ERC721 implements `name()`, `symbol()`, `decimals()`.
2. Attacker calls `OmniBridge.logMetadata(nft)`. Succeeds; emits `LogMetadata(nft, ...)`.
3. Bridge relayer submits proof to NEAR; NEAR deploys a NEP-141 token mapped to `nft`.
4. Attacker calls `nft.approve(bridge, T)` (ERC721 approval).
5. Attacker calls `OmniBridge.initTransfer(nft, T, 0, 0, "attacker.near", "")`.
   - `customMinters[nft]` is zero → skipped.
   - `isBridgeToken[nft]` is false → skipped.
   - `IERC20(nft).safeTransferFrom(attacker, bridge, T)` → dispatches selector `0x23b872dd` → ERC721's `transferFrom(attacker, bridge, T)` executes → NFT is now in bridge. Returns no data → `SafeERC20` treats as success.
   - `InitTransfer` event emitted.
6. Bridge relayer submits proof to NEAR; NEAR mints `T` NEP-141 tokens to `attacker.near`.
7. Attacker sells or transfers the NEP-141 tokens on NEAR.
8. Any attempt to call `finTransfer` for this token on EVM reverts: `IERC20(nft).safeTransfer(recipient, T)` dispatches `transfer(address,uint256)` (selector `0xa9059cbb`), which does not exist on ERC721 → permanent revert → NFT is frozen forever.

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
