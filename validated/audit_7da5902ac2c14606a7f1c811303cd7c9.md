All code references check out against the actual repository. The vulnerability is confirmed.

Audit Report

## Title
`HyperliquedBridgeToken` 3-arg `mint` permanently mis-delivers bridged funds to `_systemAddress` on `finTransfer` with non-empty message — (`File: evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

## Summary

`HyperliquedBridgeToken.mint(address, uint256, bytes)` calls `_mint(account, value)` then immediately calls `_update(account, _systemAddress, value)`, leaving `account` with zero tokens and `_systemAddress` with the full amount. `OmniBridge.finTransfer` dispatches to this 3-arg override whenever `payload.message.length != 0`. Any user who includes a non-empty `msg` when initiating a cross-chain transfer targeting HyperEVM receives zero tokens; the bridged funds are permanently stranded at `_systemAddress`.

## Finding Description

`HlBridgeToken.sol` lines 76–83 implement the 3-arg `mint`:

```solidity
function mint(address account, uint256 value, bytes memory) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);   // net: account = 0, _systemAddress = value
}
```

The contract comment (lines 29–31) explicitly labels this the "HyperCore path" — tokens are parked at `_systemAddress` to mirror HyperCore spot balances. The 2-arg `mint` (inherited from `BridgeToken`) is the "HyperEVM path" that delivers directly to the user.

`OmniBridge.finTransfer` (lines 337–349) selects between the two overloads solely on `payload.message.length`:

```solidity
} else if (isBridgeToken[payload.tokenAddress]) {
    if (payload.message.length == 0) {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount);
    } else {
        IBridgeToken(payload.tokenAddress).mint(payload.recipient, payload.amount, payload.message);
    }
}
```

`HyperliquedBridgeToken` is registered via `addCustomToken` with `customMinter = address(0)` (test line 65), so `isBridgeToken[tokenAddress] = true` and `customMinters[tokenAddress] = address(0)`, placing it squarely in this branch.

On the NEAR side (`near/omni-bridge/src/lib.rs` lines 487–499), `message` in `TransferMessagePayload` is derived from the user-supplied `msg` field of `InitTransferMsg`. A non-empty user `msg` produces a non-empty `payload.message` on the EVM side, triggering the 3-arg `mint`.

The test suite explicitly confirms the mis-delivery (`HlBridgeToken.ts` lines 75–79):

```typescript
it("mints to account then routes balance to system address", async () => {
  await token.connect(adminAccount)["mint(address,uint256,bytes)"](user1.address, 1000, "0x")
  expect(await token.balanceOf(user1.address)).to.equal(0n)
  expect(await token.balanceOf(SYSTEM_ADDRESS)).to.equal(1000n)
})
```

Recovery is impossible for the user: `coreReceiveWithData` (lines 113–122) is the only function that can move tokens out of `_systemAddress`, and it is gated to `msg.sender == _systemAddress` — a HyperCore system operation the user cannot invoke.

## Impact Explanation

**Critical — permanent loss of bridged funds.** The recipient receives 0 tokens. The full bridged amount accumulates at `_systemAddress` with no user-accessible recovery path. This directly matches the allowed impact class: *"Stealing, loss, double-spending, unauthorized minting, or permanent freezing of bridged funds."*

## Likelihood Explanation

The `msg` field is a standard, documented, user-facing parameter for cross-chain composability (e.g., DeFi calls on the destination chain). No special privileges, front-running, or external compromise is required. Any unprivileged user who sets a non-empty `msg` while targeting HyperEVM triggers the loss. The relayer simply finalizes the MPC-signed transfer as normal. The condition is trivially reachable and repeatable.

## Recommendation

The 3-arg `mint` override must not re-route tokens away from `account` for the `finTransfer` (HyperEVM delivery) path. Two viable fixes:

1. **Remove the `_update` call from the `IBridgeToken`-conforming override** and introduce a separate `mintForHyperCore` function called exclusively by `coreReceiveWithData`:

```solidity
function mint(address account, uint256 value, bytes memory) external override onlyOwner {
    _mint(account, value);
    // No _update — HyperEVM delivery goes directly to account.
}

function mintForHyperCore(address account, uint256 value) external onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);
}
```

2. **Alternatively**, if the `message` bytes are intended to carry HyperCore routing data, `finTransfer` should never call the 3-arg `mint` for `HyperliquedBridgeToken`; instead, a dedicated `IHyperCoreMinter` interface should be used so the two delivery paths are unambiguously separated.

## Proof of Concept

1. User calls `ft_transfer_call` on NEAR targeting HyperEVM with `msg = '{"InitTransfer": {"recipient": "hyp:0xUSER", ..., "msg": "some_dex_call"}}'`.
2. NEAR `sign_transfer` builds `TransferMessagePayload` with `message = b"some_dex_call"` (non-empty).
3. MPC signs; relayer calls `OmniBridge.finTransfer(signature, payload)` on HyperEVM.
4. `finTransfer` enters the `isBridgeToken` branch; `payload.message.length != 0`, so it calls `HyperliquedBridgeToken.mint(0xUSER, amount, b"some_dex_call")`.
5. Inside `mint`: `_mint(0xUSER, amount)` → user balance = `amount`; `_update(0xUSER, _systemAddress, amount)` → user balance = 0, `_systemAddress` balance = `amount`.
6. `0xUSER` receives 0 tokens. Funds are permanently stranded at `_systemAddress`.

Reproducible with the existing Hardhat suite: deploy `HyperliquedBridgeToken`, register it via `addCustomToken` with `customMinter = ZeroAddress`, and call `finTransfer` with a payload whose `message` field is non-empty. Assert `balanceOf(recipient) == 0` and `balanceOf(SYSTEM_ADDRESS) == amount`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
