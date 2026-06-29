### Title
Refunded Tokens Permanently Locked in `HyperliquedBridgeToken` Contract on NEAR-Side Failure — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

---

### Summary

When a HyperCore user initiates a cross-chain transfer via `coreReceiveWithData` with `ACTION_INIT_TRANSFER`, the `InitTransfer` event records `sender = address(HyperliquedBridgeToken)` (the token contract itself) rather than the originating HyperCore user (`from`). If the NEAR-side transfer fails and triggers an EVM refund, `finTransfer` mints the refunded tokens back to `address(HyperliquedBridgeToken)`. No withdrawal or rescue function exists in the contract, so those tokens are permanently locked.

The code itself acknowledges this in a comment:

> "The emitted InitTransfer event will carry `sender = address(this)`; the NEAR side cannot recover the originating HyperCore user (`from`) from this path." [1](#0-0) 

---

### Finding Description

**Step 1 — `coreReceiveWithData` ACTION_INIT_TRANSFER branch**

Tokens are moved from `_systemAddress` to `address(this)`, then `initTransfer` is called on the OmniBridge owner with `address(this)` as both the caller (`msg.sender`) and the `tokenAddress` argument: [2](#0-1) 

**Step 2 — `OmniBridge.initTransfer` burns and emits**

Inside `OmniBridge.initTransfer`, `msg.sender` is `address(HyperliquedBridgeToken)`. The bridge burns from `msg.sender` (the token contract) and emits `InitTransfer` with `sender = msg.sender = address(HyperliquedBridgeToken)`: [3](#0-2) [4](#0-3) 

**Step 3 — NEAR-side failure triggers refund to `address(HyperliquedBridgeToken)`**

The NEAR bridge reads `sender` from the `InitTransfer` event to determine the refund recipient. It issues a `finTransfer` back to EVM with `payload.recipient = address(HyperliquedBridgeToken)`.

**Step 4 — `finTransfer` mints to the token contract address**

Since `isBridgeToken[payload.tokenAddress]` is true and refund messages are empty, the 2-arg `mint` path is taken: [5](#0-4) 

This calls `BridgeToken.mint(address(HyperliquedBridgeToken), amount)`, which is the base class 2-arg `mint` — **not** the overridden 3-arg `mint` in `HyperliquedBridgeToken`: [6](#0-5) 

The 2-arg `mint` simply calls `_mint(account, value)` with no subsequent `_update` to `_systemAddress`. Tokens are minted directly to `address(HyperliquedBridgeToken)` and remain there.

**Step 5 — No recovery path**

`HyperliquedBridgeToken` has no `withdraw`, `rescue`, or `sweep` function. The `coreReceiveWithData` ACTION_TRANSFER path moves tokens from `_systemAddress`, not from `address(this)`. The ACTION_INIT_TRANSFER path also sources from `_systemAddress` before burning — it does not consume tokens already sitting at `address(this)`. There is no code path that can move tokens out of the contract once they are minted there. [7](#0-6) 

---

### Impact Explanation

Any HyperCore user whose cross-chain transfer fails on the NEAR side permanently loses their funds. The refunded amount is minted to the token contract address and is irrecoverable. This is a direct, permanent loss of bridged funds matching the Critical scope: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

NEAR-side transfer failures are a normal operational event (e.g., recipient account not registered, storage deposit insufficient, contract paused). Every such failure for a HyperCore-originated `ACTION_INIT_TRANSFER` results in permanent fund loss. No attacker action is required — the loss is triggered by ordinary bridge failure conditions.

---

### Recommendation

Pass the originating HyperCore user address (`from`) through the call chain so it can be recorded as the `sender` in `InitTransfer`. One approach:

1. Add a `sender` parameter to `IOmniBridgeInitTransfer.initTransfer` (or use a separate overload).
2. In `coreReceiveWithData`, pass `from` as the sender instead of `address(this)`.
3. In `OmniBridge.initTransfer`, use the explicit `sender` argument for the event rather than `msg.sender`.

Alternatively, store a `pendingRefund[nonce] = from` mapping in `HyperliquedBridgeToken` before calling `initTransfer`, and implement a `claimRefund` function that transfers tokens from `address(this)` back to the stored originator when a refund arrives.

---

### Proof of Concept

```solidity
// 1. System address calls coreReceiveWithData with ACTION_INIT_TRANSFER
//    from = alice (HyperCore user), amount = 100e18, message = ""
token.coreReceiveWithData(
    alice,
    bytes32(0), uint32(0),
    100e18, uint64(0),
    abi.encodePacked(uint8(1), abi.encode(uint128(0), "near:bob.near", ""))
);
// InitTransfer emitted: sender = address(token), not alice

// 2. Simulate NEAR-side failure: relayer calls finTransfer with recipient = address(token)
bridge.finTransfer(
    validSignature,
    TransferMessagePayload({
        tokenAddress: address(token),
        recipient:    address(token),   // refund target = token contract
        amount:       100e18,
        message:      "",               // empty → 2-arg mint path
        ...
    })
);

// 3. Assert tokens are locked
assert(token.balanceOf(address(token)) == 100e18);
// No function exists to recover them; alice's 100e18 is permanently lost.
```

### Citations

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L103-105)
```text
    ///   OmniAddress string (e.g. `near:alice.near`, `sol:<base58>`). nativeFee = 0.
    /// The emitted InitTransfer event will carry `sender = address(this)`; the NEAR
    /// side cannot recover the originating HyperCore user (`from`) from this path.
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L120-138)
```text
        if (action == ACTION_TRANSFER) {
            address recipient = abi.decode(tail, (address));
            _update(_systemAddress, recipient, amount);
        } else if (action == ACTION_INIT_TRANSFER) {
            (uint128 fee, string memory recipient, string memory message) = abi
                .decode(tail, (uint128, string, string));
            uint128 amount128 = amount.toUint128();
            _update(_systemAddress, address(this), amount);
            IOmniBridgeInitTransfer(owner()).initTransfer(
                address(this),
                amount128,
                fee,
                0,
                recipient,
                message
            );
        } else {
            revert UnknownAction(action);
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-342)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L404-406)
```text
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
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

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L50-52)
```text
    function mint(address beneficiary, uint256 amount) external onlyOwner {
        _mint(beneficiary, amount);
    }
```
