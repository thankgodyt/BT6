All cited code references check out against the actual repository. Let me verify the key facts:

1. `HlBridgeToken.sol` lines 76–83: The 3-arg `mint` calls `_mint(account, value)` then `_update(account, _systemAddress, value)`, leaving `account` with zero tokens. [1](#0-0) 

2. `OmniBridge.sol` lines 337–349: The sole dispatch condition is `payload.message.length == 0`. Any non-empty `message` routes to the 3-arg overload. [2](#0-1) 

3. `OmniBridge.sol` line 287: The nonce is marked consumed before the mint call, preventing replay. [3](#0-2) 

4. `HlBridgeToken.ts` lines 75–79: The test suite explicitly confirms `balanceOf(user1) == 0` and `balanceOf(SYSTEM_ADDRESS) == 1000` after the 3-arg mint. [4](#0-3) 

5. `IBridgeToken.sol`: Both overloads are declared; the dispatch is type-safe with no interface-level guard. [5](#0-4) 

---

Audit Report

## Title
Recipient Receives Zero Tokens When `finTransfer` Calls 3-arg `mint` on `HyperliquedBridgeToken` — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

## Summary
`HyperliquedBridgeToken.mint(address, uint256, bytes)` is the HyperCore minting path: it calls `_mint(account, value)` then immediately `_update(account, _systemAddress, value)`, transferring all newly minted tokens to `_systemAddress` and leaving the recipient with zero. `OmniBridge.finTransfer()` dispatches to this 3-arg overload whenever `payload.message.length > 0`. Any NEAR-signed `finTransfer` payload carrying a non-empty `message` field targeting a registered `HyperliquedBridgeToken` will therefore deliver zero tokens to the recipient while permanently parking the full bridged amount at `_systemAddress`, with the nonce consumed and no replay possible.

## Finding Description
**Root cause:** `HyperliquedBridgeToken.mint(address, uint256, bytes)` (lines 76–83 of `HlBridgeToken.sol`) unconditionally drains the minted balance to `_systemAddress` regardless of the `bytes` argument content (the parameter has no name and is never read). The `_update(account, _systemAddress, value)` call is an ERC-20 internal transfer, not a mint; it moves all `value` tokens from `account` to `_systemAddress`. Net recipient balance after both calls: zero.

**Dispatch path in `OmniBridge.finTransfer()` (lines 337–349 of `OmniBridge.sol`):**
```
} else if (isBridgeToken[payload.tokenAddress]) {
    if (payload.message.length == 0) {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
    } else {
        IBridgeToken(payload.tokenAddress).mint(
            payload.recipient, payload.amount, payload.message   // 3-arg path
        );
    }
}
```
The sole branching condition is `payload.message.length == 0`. Any non-empty `message` — regardless of content or intent — routes to the 3-arg overload.

**Exploit flow:**
1. Attacker or innocent user initiates a NEAR→HyperEVM transfer of a `HyperliquedBridgeToken` with any non-empty `message` field (e.g., a DeFi routing hint, a memo, or a single byte).
2. The NEAR bridge signs the payload; `ECDSA.recover` at line 311 passes — the signature is valid.
3. `completedTransfers[nonce]` is set to `true` at line 287 before the mint.
4. `finTransfer` dispatches to the 3-arg `mint`; `_mint(recipient, amount)` runs, then `_update(recipient, _systemAddress, amount)` immediately drains the balance.
5. Recipient balance = 0. `_systemAddress` balance += `amount`. Nonce consumed.

**Why existing checks fail:** Signature verification (line 311) only proves payload authenticity; it does not constrain what the token contract does with minted tokens. The `isBridgeToken` check (line 337) confirms registration but does not distinguish HyperCore-bound from HyperEVM-bound transfers. There is no bridge-level guard preventing the 3-arg call on a `HyperliquedBridgeToken` when the intent is HyperEVM delivery.

**Recovery path is not guaranteed:** `coreReceiveWithData` (the only function that moves tokens out of `_systemAddress`) requires `msg.sender == _systemAddress` — a Hyperliquid system-level actor with no protocol obligation to return funds that arrived via an EVM bridge call with an arbitrary message.

## Impact Explanation
Permanent loss of bridged funds: any user who bridges tokens to a `HyperliquedBridgeToken` address while attaching a non-empty `message` receives zero tokens, the full amount is parked at `_systemAddress`, and the transfer nonce is consumed preventing any replay or refund at the bridge level. This matches the allowed critical impact: "Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."

## Likelihood Explanation
`HyperliquedBridgeToken` is a production contract registered via `addCustomToken` with `customMinter = address(0)`, placing it in the `isBridgeToken` branch. The NEAR bridge's `message` field is a documented, supported production feature used for cross-contract calls and DeFi routing. No special attacker capability is required: any user who attaches any non-empty `message` to a transfer targeting a `HyperliquedBridgeToken` triggers the loss. The condition is trivially satisfiable (a single non-zero byte suffices). The loss is repeatable across any number of distinct nonces.

## Recommendation
Override the 3-arg `mint` in `HyperliquedBridgeToken` to distinguish between HyperCore-bound and HyperEVM-bound delivery. One concrete approach: treat a non-empty `message` as a HyperEVM delivery (call `_mint(account, value)` only, matching `BridgeToken`'s base behavior) and expose the `_update` drain only through a separate, explicitly named entry point callable only by `_systemAddress`. Alternatively, add a revert guard in the 3-arg `mint` if the intent is always HyperCore-only, and enforce at the bridge level (e.g., via a registry flag on the token) that `HyperliquedBridgeToken` addresses must never be targeted with a non-empty `message` in `finTransfer`, reverting instead of silently draining.

## Proof of Concept
The existing test at `evm/tests/HlBridgeToken.ts` lines 75–79 already proves the 3-arg mint outcome in isolation:
```typescript
await token.connect(adminAccount)["mint(address,uint256,bytes)"](user1.address, 1000, "0x")
expect(await token.balanceOf(user1.address)).to.equal(0n)
expect(await token.balanceOf(SYSTEM_ADDRESS)).to.equal(1000n)
```
End-to-end proof via `finTransfer`:
1. Deploy `HyperliquedBridgeToken` with a mock `_systemAddress`.
2. Register it on `OmniBridge` via `addCustomToken` with `customMinter = address(0)`.
3. Transfer ownership to `OmniBridge`.
4. Build a `TransferMessagePayload` with `message = "0x01"` (any non-empty bytes) targeting the registered token.
5. Sign with the `testWallet` key (already used as `nearBridgeDerivedAddress` in the test suite's `beforeEach`).
6. Call `OmniBridge.finTransfer(signature, payload)`.
7. Assert: `token.balanceOf(recipient) == 0`, `token.balanceOf(SYSTEM_ADDRESS) == payload.amount`, `completedTransfers[nonce] == true`.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-287)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;
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

**File:** evm/tests/HlBridgeToken.ts (L75-79)
```typescript
    it("mints to account then routes balance to system address", async () => {
      await token.connect(adminAccount)["mint(address,uint256,bytes)"](user1.address, 1000, "0x")
      expect(await token.balanceOf(user1.address)).to.equal(0n)
      expect(await token.balanceOf(SYSTEM_ADDRESS)).to.equal(1000n)
    })
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
