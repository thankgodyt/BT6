Let me read the key functions more carefully to confirm the finding.

### Title
Unregistered ERC1155 Token IDs Accepted by `initTransfer1155` Cause Permanent Fund Freezing - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

`initTransfer1155` in `OmniBridge.sol` does not verify that the `(tokenAddress, tokenId)` pair has been registered via `logMetadata1155` before accepting an ERC1155 deposit. The `multiTokens` mapping returns a zero-value struct by default for unregistered pairs, and this default is never validated. Any user can call `initTransfer1155` with an unregistered ERC1155 token, transferring it into the bridge contract where it becomes permanently frozen with no recovery path.

---

### Finding Description

The `multiTokens` mapping stores `MultiTokenInfo{tokenAddress, tokenId}` for each registered ERC1155 token, keyed by a deterministic address derived from `keccak256(abi.encodePacked(tokenAddress, tokenId))`. Registration happens in `logMetadata1155`, which sets `multiTokens[deterministicToken].tokenAddress` to a non-zero value.

`initTransfer1155` computes `deterministicToken` and immediately transfers the ERC1155 tokens to the bridge, then emits `InitTransfer` — **without ever checking whether `multiTokens[deterministicToken].tokenAddress != address(0)`**:

```solidity
// OmniBridge.sol lines 453–489
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
// ← No check: multiTokens[deterministicToken].tokenAddress != address(0)

emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, ...);
```

This is the direct analog of the original bug: `multiTokens[deterministicToken]` silently returns the zero struct (default) for any unregistered `(tokenAddress, tokenId)` pair, and the function treats this as valid, accepting the deposit.

When `finTransfer` is later called with `payload.tokenAddress = deterministicToken`:

```solidity
// OmniBridge.sol lines 315–354
MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress]; // zero struct
if (payload.tokenAddress == address(0)) { ... }
else if (multiToken.tokenAddress != address(0)) { ... }  // false — unset
else if (customMinters[payload.tokenAddress] != address(0)) { ... }  // false — unset
else if (isBridgeToken[payload.tokenAddress]) { ... }  // false — unset
else {
    IERC20(payload.tokenAddress).safeTransfer(...);  // reverts: deterministicToken is not ERC20
}
```

`finTransfer` reverts because `deterministicToken` is a hash-derived address, not an ERC20 contract. The ERC1155 tokens are permanently locked in the bridge with no admin rescue function.

The test suite itself confirms the vulnerability is reachable: the test `"validates ERC1155 receiver hooks"` (line 193) calls `initTransfer1155` **without** a prior `logMetadata1155` call and it succeeds, demonstrating the missing guard.

---

### Impact Explanation

ERC1155 tokens deposited via `initTransfer1155` for an unregistered `(tokenAddress, tokenId)` pair are permanently frozen in the bridge contract. There is no admin function to rescue stuck ERC1155 tokens. The NEAR side cannot finalize the transfer because `deterministicToken` is not registered there either. This constitutes permanent freezing of bridged funds.

---

### Likelihood Explanation

`initTransfer1155` is a public, permissionless function. Any user who calls it without first calling `logMetadata1155` — whether by mistake or by design — will permanently lose their ERC1155 tokens. The protocol provides no on-chain enforcement of the required ordering, making accidental loss realistic for any ERC1155 user interacting with the bridge.

---

### Recommendation

Add a registration check at the start of `initTransfer1155` before accepting the ERC1155 deposit:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);
require(
    multiTokens[deterministicToken].tokenAddress != address(0),
    "ERR_TOKEN_NOT_REGISTERED"
);
```

This mirrors the fix applied in the referenced report: revert when the mapping is unset rather than silently accepting a default zero value as valid.

---

### Proof of Concept

1. Deploy `OmniBridge` and an ERC1155 token contract.
2. Mint ERC1155 `tokenId = 1` to `attacker`.
3. Approve the bridge to spend `attacker`'s tokens.
4. Call `initTransfer1155(erc1155Address, 1, amount, 0, 0, "victim.near", "")` **without** calling `logMetadata1155` first.
5. The call succeeds: ERC1155 tokens are transferred to the bridge, `InitTransfer` is emitted with `deterministicToken`.
6. `multiTokens[deterministicToken].tokenAddress == address(0)` — the token is unregistered.
7. Any attempt to call `finTransfer` with `payload.tokenAddress = deterministicToken` reverts at the `IERC20(...).safeTransfer(...)` fallback.
8. The ERC1155 tokens are permanently frozen in the bridge with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L47-48)
```text
    mapping(address => address) public customMinters;
    mapping(address => MultiTokenInfo) public multiTokens;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L234-255)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-464)
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
```

**File:** evm/tests/OmniBridge1155.test.ts (L191-194)
```typescript
    await bridge
      .connect(user)
      .initTransfer1155(await erc1155.getAddress(), tokenId, 1, 0, 0, "receiver.near", "")
    expect(await erc1155.balanceOf(bridgeAddress, tokenId)).to.equal(1n)
```
