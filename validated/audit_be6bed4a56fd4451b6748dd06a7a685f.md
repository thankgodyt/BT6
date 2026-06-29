### Title
`OmniBridge::initTransfer` Accepts ERC721 Tokens, Permanently Locking NFTs in the Bridge - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`OmniBridge.sol::initTransfer` performs no validation that the supplied `tokenAddress` is a registered ERC20 token. Because ERC721's `transferFrom(address,address,uint256)` shares the same ABI selector as ERC20's `transferFrom`, and OpenZeppelin's `SafeERC20.safeTransferFrom` treats a void return as success, a user can call `initTransfer` with an ERC721 contract address and a `tokenId` cast to `uint128` as the `amount`. The NFT is transferred into the bridge, an `InitTransfer` event is emitted, but the NEAR-side `fin_transfer_callback` panics with `TokenDecimalsNotFound` because the ERC721 was never registered. The NFT is permanently locked with no recovery path.

---

### Finding Description

`OmniBridge.sol::initTransfer` accepts any `tokenAddress` without checking whether it is a registered or known ERC20 token: [1](#0-0) 

For any address that is not a bridge token and has no custom minter, the function falls into the `else` branch and calls:

```solidity
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
```

OpenZeppelin's `SafeERC20._callOptionalReturn` only reverts if the low-level call itself reverts **or** if it returns data that decodes to `false`. ERC721's `transferFrom` returns `void` (no return data), so `returndata.length == 0` and the check is skipped — the call is treated as successful. The NFT is transferred into the bridge.

The `amount` parameter is `uint128`. When ABI-encoded for the `transferFrom` call it is zero-padded to `uint256`, so it is interpreted by the ERC721 contract as the `tokenId`. This works for any tokenId that fits in 128 bits (the vast majority of practical NFTs).

An `InitTransfer` event is emitted with the ERC721 address and the tokenId as `amount`: [2](#0-1) 

On the NEAR side, `fin_transfer_callback` is invoked after proof verification. It immediately looks up the token's registered decimals: [3](#0-2) 

Because the ERC721 was never registered via `logMetadata` + `deploy_token`, `token_decimals.get(...)` returns `None` and the callback panics with `BridgeError::TokenDecimalsNotFound`. The NEAR transaction fails. The NFT remains locked in the EVM bridge contract forever.

The `logMetadata` function cannot be used to pre-register an ERC721 token because it calls `IERC20Metadata(tokenAddress).decimals()`, which ERC721 tokens do not implement and which will revert: [4](#0-3) 

There is no admin rescue function in `OmniBridge.sol` to recover stuck tokens. The only egress path for locked tokens is `finTransfer`, which requires a valid NEAR MPC signature — a signature that can never be produced because the NEAR side will always panic for an unregistered token.

---

### Impact Explanation

**Critical.** Any ERC721 token sent through `initTransfer` is permanently and irrecoverably locked in the `OmniBridge` contract. The user loses their NFT with no recourse. This is a direct, permanent loss of bridged funds triggered by a single unprivileged user action.

---

### Likelihood Explanation

**Medium.** The `initTransfer` function is the primary public entry point for EVM→NEAR transfers. A user who mistakenly (or experimentally) passes an ERC721 address will lose their NFT. The interface accepts any `tokenAddress` with no guard, and the ERC721/ERC20 interface overlap makes the mistake easy. No special privileges or preconditions are required beyond token approval.

---

### Recommendation

Add a token registration check in `initTransfer` to ensure only known/registered tokens can be bridged. One approach: require that the token has been registered via `logMetadata` (i.e., maintain a set of tokens for which a `LogMetadata` event has been emitted and accepted). Alternatively, call `IERC20Metadata(tokenAddress).decimals()` inside `initTransfer` and revert if it fails, since ERC20 tokens must implement `decimals()` while ERC721 tokens do not.

---

### Proof of Concept

1. Deploy a standard ERC721 contract (e.g., OpenZeppelin `ERC721`).
2. Mint tokenId `5` to `user`.
3. `user` calls `erc721.approve(omniBridgeAddress, 5)`.
4. `user` calls `omniBridge.initTransfer(erc721Address, 5, 1, 0, "user.near", "")`.
   - `safeTransferFrom(user, bridge, 5)` succeeds (ERC721 `transferFrom` returns void; SafeERC20 treats this as success).
   - `InitTransfer` event is emitted with `tokenAddress = erc721Address`, `amount = 5`.
   - `user` no longer owns tokenId 5; it is held by `OmniBridge`.
5. A relayer submits the proof to NEAR `fin_transfer`.
6. `fin_transfer_callback` panics: `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)`.
7. The NEAR transaction reverts. The NFT is permanently locked in `OmniBridge` with no recovery path.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
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
```

**File:** near/omni-bridge/src/lib.rs (L715-718)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);
```
