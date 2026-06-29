### Title
Recipient Receives Zero Tokens When `finTransfer` Calls 3-arg `mint` on `HyperliquedBridgeToken` — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

---

### Summary

`HyperliquedBridgeToken.mint(address, uint256, bytes)` is designed for the HyperCore minting path: it calls `_mint(account, value)` then immediately `_update(account, _systemAddress, value)`, leaving the recipient with zero tokens. `OmniBridge.finTransfer()` dispatches to this 3-arg overload whenever `payload.message.length > 0`. Any legitimately NEAR-signed `finTransfer` payload that carries a non-empty `message` field and targets a registered `HyperliquedBridgeToken` will therefore deliver zero tokens to the recipient while permanently parking the full amount at `_systemAddress`.

---

### Finding Description

**`HyperliquedBridgeToken.mint(address, uint256, bytes)` — `evm/src/omni-bridge/contracts/HlBridgeToken.sol` lines 76–83:**

```solidity
function mint(
    address account,
    uint256 value,
    bytes memory          // ← parameter is completely ignored
) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);   // ← immediately drains account
}
``` [1](#0-0) 

After `_mint`, `account` holds `value` tokens. `_update(account, _systemAddress, value)` is an ERC-20 internal transfer that moves all `value` tokens from `account` to `_systemAddress`. Net balance of `account` after both calls: **zero**. The test suite confirms this explicitly:

```typescript
await token["mint(address,uint256,bytes)"](user1.address, 1000, "0x")
expect(await token.balanceOf(user1.address)).to.equal(0n)
expect(await token.balanceOf(SYSTEM_ADDRESS)).to.equal(1000n)
``` [2](#0-1) 

**`OmniBridge.finTransfer()` dispatch — `evm/src/omni-bridge/contracts/OmniBridge.sol` lines 337–349:**

```solidity
} else if (isBridgeToken[payload.tokenAddress]) {
    if (payload.message.length == 0) {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
    } else {
        IBridgeToken(payload.tokenAddress).mint(
            payload.recipient, payload.amount, payload.message   // ← 3-arg path
        );
    }
}
``` [3](#0-2) 

The sole branching condition is `payload.message.length == 0`. Any non-empty `message` — regardless of content — routes to the 3-arg overload. The `bytes memory` parameter in `HyperliquedBridgeToken.mint` has no variable name and is never read; the HyperCore drain happens unconditionally.

**Signature verification does not protect against this.** The NEAR bridge legitimately signs payloads that include a `message` field (for cross-contract call / DeFi-routing use cases). The signature check at line 311 only proves the payload is authentic; it does not constrain what the token contract does with the minted tokens. [4](#0-3) 

**`IBridgeToken` interface — `evm/src/common/IBridgeToken.sol`:**

Both overloads are declared in the interface, so the dispatch is type-safe and compiles without warning. There is no interface-level or bridge-level guard that prevents calling the 3-arg overload on a `HyperliquedBridgeToken`. [5](#0-4) 

---

### Impact Explanation

- **Recipient balance = 0** after a valid `finTransfer` that carries any non-empty `message`.
- **Tokens are permanently parked at `_systemAddress`.** The only recovery path is `coreReceiveWithData`, which requires `msg.sender == _systemAddress` — a Hyperliquid system-level actor with no obligation to return funds that arrived via an EVM bridge call.
- **No bridge-level refund or retry mechanism exists.** The nonce is marked `completedTransfers[nonce] = true` before the mint call, so the transfer cannot be replayed. [6](#0-5) 

Impact category: **Critical — permanent loss of bridged funds**.

---

### Likelihood Explanation

- `HyperliquedBridgeToken` is a production contract registered via `addCustomToken` with `customMinter = address(0)`, placing it in the `isBridgeToken` branch.
- The NEAR bridge's cross-contract call feature (attaching a `message` to a transfer) is a documented, supported production path. Any user who bridges tokens to a `HyperliquedBridgeToken` address while attaching a message (e.g., for a DeFi interaction on HyperEVM) triggers the loss.
- No special attacker capability is required beyond initiating a standard cross-chain transfer with a non-empty message field.

---

### Recommendation

Override the 3-arg `mint` in `HyperliquedBridgeToken` to distinguish between the HyperCore-bound path and a plain HyperEVM delivery. One approach: treat a non-empty `message` as a HyperEVM delivery (call `_mint(account, value)` only, matching `BridgeToken`'s base behavior), and reserve the `_update` drain for an explicit, separate entry point callable only by `_systemAddress`. Alternatively, document and enforce at the bridge level that `HyperliquedBridgeToken` addresses must never be targeted with a non-empty `message`, and add a revert guard in the 3-arg `mint` if called with a non-empty `bytes` argument when the intent is HyperEVM delivery.

---

### Proof of Concept

```solidity
// Local hardhat test — no mainnet interaction
// 1. Deploy HyperliquedBridgeToken with a mock _systemAddress
// 2. Register it on OmniBridge (isBridgeToken = true, customMinter = address(0))
// 3. Transfer ownership to OmniBridge
// 4. Build a TransferMessagePayload with message = "0x01" (any non-empty bytes)
// 5. Sign with the test nearBridgeDerivedAddress key
// 6. Call OmniBridge.finTransfer(signature, payload)
// Assert:
//   recipient.balanceOf == 0
//   systemAddress.balanceOf == payload.amount
```

The existing test at `evm/tests/HlBridgeToken.ts` lines 75–79 already proves step 6's outcome in isolation. Wiring it through `finTransfer` with a signed payload (using the `testWallet` helper already present in the test suite) completes the end-to-end proof. [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L76-83)
```text
    function mint(
        address account,
        uint256 value,
        bytes memory
    ) external override onlyOwner {
        _mint(account, value);
        _update(account, _systemAddress, value);
    }
```

**File:** evm/tests/HlBridgeToken.ts (L68-86)
```typescript
  describe("3-arg mint (HyperCore path)", () => {
    let token: HyperliquedBridgeToken

    beforeEach(async () => {
      ;({ token } = await deployHlToken())
    })

    it("mints to account then routes balance to system address", async () => {
      await token.connect(adminAccount)["mint(address,uint256,bytes)"](user1.address, 1000, "0x")
      expect(await token.balanceOf(user1.address)).to.equal(0n)
      expect(await token.balanceOf(SYSTEM_ADDRESS)).to.equal(1000n)
    })

    it("rejects non-owner callers", async () => {
      await expect(
        token.connect(user1)["mint(address,uint256,bytes)"](user1.address, 1000, "0x"),
      ).to.be.revertedWithCustomError(token, "OwnableUnauthorizedAccount")
    })
  })
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L309-313)
```text
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-349)
```text
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
```

**File:** evm/src/common/IBridgeToken.sol (L4-14)
```text
interface IBridgeToken {
    function mint(address account, uint256 value) external;

    function mint(
        address account,
        uint256 value,
        bytes memory message
    ) external;

    function burn(address account, uint256 value) external;
}
```
