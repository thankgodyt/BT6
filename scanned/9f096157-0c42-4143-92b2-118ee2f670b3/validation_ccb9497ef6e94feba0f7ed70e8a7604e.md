### Title
Reentrancy via User-Controlled Token Callback Corrupts `currentOriginNonce`, Enabling Unauthorized Minting on NEAR — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` and `initTransfer` in `OmniBridge.sol` read `currentOriginNonce` **after** an external call to a user-supplied token contract. A malicious ERC1155 token (or ERC777-compatible ERC20) can reenter `initTransfer1155` during `safeTransferFrom`, causing two `InitTransfer` events to be emitted with the **same nonce** while no tokens are actually locked. The NEAR side processes the first proof submitted and mints tokens on NEAR without any corresponding locked collateral on EVM.

---

### Finding Description

In `initTransfer1155` (lines 439–490 of `OmniBridge.sol`):

```solidity
function initTransfer1155(...) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
    currentOriginNonce += 1;                          // (1) nonce incremented to N+1

    address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

    IERC1155(tokenAddress).safeTransferFrom(          // (2) external call to user-controlled token
        msg.sender,
        address(this),
        tokenId,
        amount,
        ""
    );
    // ← reentrant call can happen here; nonce becomes N+2, inner InitTransfer emitted with N+2

    uint256 extensionValue = msg.value - nativeFee;

    initTransferExtension(
        msg.sender,
        deterministicToken,
        currentOriginNonce,                           // (3) reads CURRENT nonce (now N+2, not N+1)
        ...
    );

    emit BridgeTypes.InitTransfer(
        msg.sender,
        deterministicToken,
        currentOriginNonce,                           // (4) emits with N+2 — DUPLICATE of inner call
        ...
    );
}
```

The root cause is that `currentOriginNonce` is **read at event-emission time** (step 3–4), not captured at increment time (step 1). A reentrant call modifies `currentOriginNonce` between steps 1 and 3, so the outer call emits an `InitTransfer` event with the nonce value written by the inner call.

No `nonReentrant` guard exists anywhere in the EVM source tree (confirmed by grep). The CLAUDE.md security invariant "State before external calls" is satisfied for `finTransfer` (nonce marked used before external call) but **not enforced** for `initTransfer1155` or `initTransfer`, where the nonce is incremented but then re-read after the external call.

The same structural flaw exists in `initTransfer` (lines 373–437) via ERC777 `tokensReceived` hooks, which fire during `safeTransferFrom` on ERC777-compatible tokens.

---

### Impact Explanation

The attacker deploys a malicious ERC1155 token whose `safeTransferFrom` reenters `initTransfer1155`. The reentrant (inner) call:
- Increments `currentOriginNonce` to N+2
- Calls `safeTransferFrom` again (malicious token returns without transferring any tokens)
- Emits `InitTransfer` with nonce N+2

The outer call resumes and:
- Reads `currentOriginNonce` = N+2 (corrupted by inner call)
- Emits a second `InitTransfer` with nonce N+2 (duplicate)
- Nonce N+1 is never emitted

The NEAR side sees two on-chain `InitTransfer` events with nonce N+2. A relayer submits a proof of the inner event (where no tokens were locked). NEAR's `fin_transfer_callback` processes it and mints/unlocks tokens for the recipient. The second proof (outer event, same nonce) is rejected as a replay. The attacker receives bridged tokens on NEAR with zero EVM collateral locked.

Impact: **unauthorized minting of bridged tokens on NEAR** — direct theft of protocol funds.

---

### Likelihood Explanation

Any unprivileged user can call `initTransfer1155` with an arbitrary `tokenAddress`. Deploying a malicious ERC1155 contract requires no special permissions. The ERC1155 `safeTransferFrom` callback path is guaranteed by the standard (not optional like ERC777). The bridge has no allowlist for ERC1155 tokens in `initTransfer1155`. The attack requires one transaction and one malicious contract deployment.

---

### Recommendation

1. **Capture the nonce into a local variable immediately after increment** and use that local variable in all subsequent reads (extension call and event emission):

```solidity
uint64 nonce = ++currentOriginNonce;
// ... external call ...
initTransferExtension(msg.sender, deterministicToken, nonce, ...);
emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, nonce, ...);
```

2. **Add `ReentrancyGuardUpgradeable`** from OpenZeppelin and apply `nonReentrant` to `initTransfer`, `initTransfer1155`, and `finTransfer`.

Apply the same local-variable fix to `initTransfer` (line 381 / line 418 / line 430).

---

### Proof of Concept

**Malicious ERC1155 contract:**
```solidity
contract MaliciousERC1155 is ERC1155 {
    OmniBridge bridge;
    bool reentered;

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory) public override {
        if (!reentered) {
            reentered = true;
            // Reenter: no tokens actually transferred in either call
            bridge.initTransfer1155(address(this), id, amount, 0, 0, "attacker.near", "");
        }
        // Return without updating any balances — tokens never locked
    }
}
```

**Attack sequence:**
1. Deploy `MaliciousERC1155` pointing to `OmniBridge`.
2. Call `bridge.initTransfer1155(malicious, tokenId, amount, 0, 0, "attacker.near", "")`.
3. Bridge increments `currentOriginNonce` to N+1, calls `malicious.safeTransferFrom(...)`.
4. Malicious token reenters: bridge increments nonce to N+2, inner `InitTransfer(nonce=N+2)` emitted, no tokens transferred.
5. Outer call resumes: reads `currentOriginNonce = N+2`, emits second `InitTransfer(nonce=N+2)`, no tokens transferred.
6. Relayer submits proof of inner `InitTransfer(nonce=N+2)` to NEAR.
7. NEAR mints tokens to `attacker.near` — zero EVM collateral locked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-45)
```text
    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
