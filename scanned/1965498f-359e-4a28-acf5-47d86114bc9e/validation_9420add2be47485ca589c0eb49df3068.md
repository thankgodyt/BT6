### Title
`HyperliquedBridgeToken` 3-arg `mint` routes bridged funds to `_systemAddress` instead of `payload.recipient` on `finTransfer` with non-empty message — (`File: evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

---

### Summary

`HyperliquedBridgeToken` overrides the 3-arg `mint(address account, uint256 value, bytes memory)` to immediately re-route all newly minted tokens from `account` to `_systemAddress` via `_update(account, _systemAddress, value)`. `OmniBridge.finTransfer` selects the 3-arg `mint` whenever `payload.message.length != 0`. Any user who includes a non-empty `msg` when initiating a cross-chain transfer to HyperEVM will have their tokens permanently deposited to `_systemAddress` instead of to themselves, resulting in total loss of bridged funds.

---

### Finding Description

`HyperliquedBridgeToken` documents two distinct mint paths:

- **2-arg `mint(address, uint256)`** (inherited from `BridgeToken`): mints directly to `account` — intended for HyperEVM delivery.
- **3-arg `mint(address, uint256, bytes)`** (overridden): mints to `account` then calls `_update(account, _systemAddress, value)` — intended for HyperCore spot-balance tracking. [1](#0-0) 

The net effect of the 3-arg override is that `account` receives 0 tokens and `_systemAddress` receives `value` tokens. This is confirmed by the test suite: [2](#0-1) 

`OmniBridge.finTransfer` dispatches to the 3-arg `mint` whenever `payload.message.length != 0`: [3](#0-2) 

`HyperliquedBridgeToken` is registered as a bridge token (`isBridgeToken[tokenAddress] = true`) via `addCustomToken` with `customMinter = address(0)`, placing it squarely in this branch: [4](#0-3) 

On the NEAR side, the `message` field in the signed `TransferMessagePayload` is populated from the user-supplied `msg` field of `InitTransferMsg` via `sign_transfer`: [5](#0-4) 

When a user sets a non-empty `msg` in their `InitTransferMsg` targeting HyperEVM, the resulting MPC-signed EVM payload carries a non-empty `message` bytes field. `finTransfer` then calls `mint(payload.recipient, payload.amount, payload.message)`, which routes all tokens to `_systemAddress` instead of `payload.recipient`.

---

### Impact Explanation

**Critical — permanent loss of bridged funds.**

The recipient receives 0 tokens. The tokens accumulate at `_systemAddress` (the HyperCore system address), which is a protocol-controlled address. There is no user-accessible path to recover them: `coreReceiveWithData` with `ACTION_TRANSFER` can release tokens from `_systemAddress`, but it is gated to `msg.sender == _systemAddress` — a HyperCore system operation the user cannot invoke. [6](#0-5) 

Every token bridged to HyperEVM with a non-empty `message` is permanently mis-delivered.

---

### Likelihood Explanation

The `msg` field in `InitTransferMsg` is a standard, documented, user-facing parameter used for cross-chain message passing (e.g., DeFi composability calls on the destination chain). Any unprivileged user who exercises this feature while targeting HyperEVM triggers the loss. No special privileges, front-running, or external compromise is required. The relayer simply finalizes the transfer as signed by MPC.

---

### Recommendation

The 3-arg `mint` override in `HyperliquedBridgeToken` must not re-route tokens away from `account`. For HyperEVM delivery (the `finTransfer` path), the 3-arg override should behave identically to the base `BridgeToken` implementation — minting directly to `account` without the `_update` call:

```solidity
// Fix: remove the _update re-route for the finTransfer (HyperEVM) path
function mint(
    address account,
    uint256 value,
    bytes memory
) external override onlyOwner {
    _mint(account, value);
    // Do NOT call _update(account, _systemAddress, value) here.
    // That re-route is only correct for the HyperCore accounting path,
    // which is handled exclusively via coreReceiveWithData.
}
```

Alternatively, introduce a dedicated `mintForHyperCore` function used only by `coreReceiveWithData`, and keep the `IBridgeToken`-conforming `mint` overrides free of the `_systemAddress` re-route.

---

### Proof of Concept

1. User calls `ft_transfer_call` on NEAR targeting HyperEVM, with `msg` = `{"InitTransfer": {"recipient": "hyp:0xUSER", "fee": "0", "native_token_fee": "0", "msg": "some_dex_call"}}`.
2. NEAR bridge stores the transfer; `sign_transfer` builds `TransferMessagePayload` with `message = b"some_dex_call"` (non-empty).
3. MPC signs the payload; relayer calls `OmniBridge.finTransfer(signature, payload)` on HyperEVM.
4. `finTransfer` enters the `isBridgeToken` branch and, because `payload.message.length != 0`, calls `HyperliquedBridgeToken.mint(0xUSER, amount, b"some_dex_call")`.
5. Inside `mint`: `_mint(0xUSER, amount)` — user's balance = `amount`. Then `_update(0xUSER, _systemAddress, amount)` — user's balance = 0, `_systemAddress` balance = `amount`.
6. `0xUSER` receives 0 tokens. Funds are permanently stranded at `_systemAddress`. [1](#0-0) [3](#0-2)

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

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L113-122)
```text
    ) external override {
        if (msg.sender != _systemAddress) revert NotSystemAddress();
        if (data.length == 0) revert EmptyActionData();

        uint8 action = uint8(data[0]);
        bytes calldata tail = data[1:];

        if (action == ACTION_TRANSFER) {
            address recipient = abi.decode(tail, (address));
            _update(_systemAddress, recipient, amount);
```

**File:** evm/tests/HlBridgeToken.ts (L61-66)
```typescript
  // `addCustomToken` with `customMinter = address(0)` registers the token so that
  // `OmniBridge.initTransfer` falls into the `isBridgeToken` branch and calls
  // `BridgeToken.burn(msg.sender, amount)` — exactly the path we want.
  async function registerHlOnBridge(tokenAddress: string) {
    await omniBridge.addCustomToken(NEAR_TOKEN_ID, tokenAddress, ethers.ZeroAddress, 18)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
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
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L487-500)
```rust
        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
```
