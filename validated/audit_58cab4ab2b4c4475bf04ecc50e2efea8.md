Audit Report

## Title
Missing Self-Address Guard in `ACTION_TRANSFER` Allows Permanent Token Stranding at `address(this)` — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

## Summary

`coreReceiveWithData` in `HyperliquedBridgeToken` dispatches `ACTION_TRANSFER` without validating that the decoded `recipient` is not `address(this)`. A HyperCore user can supply `recipient = tokenContractAddress` via `sendToEvmWithData`, causing tokens to be transferred into the token contract itself with no recovery path. Any subsequent `ACTION_INIT_TRANSFER` call burns only its own `amount`, leaving the earlier deposit permanently stranded and creating irrecoverable accounting drift between HyperCore and HyperEVM.

## Finding Description

In `HlBridgeToken.sol`, `coreReceiveWithData` is callable only by `_systemAddress` (line 114), which acts as a relay forwarding HyperCore user-supplied `data` from `sendToEvmWithData`. The contract's own NatSpec confirms this: *"HyperCore user triggers `sendToEvmWithData` targeting this token"* and *"data == 0x00 || abi.encode(address recipient): release `amount` from the pool to the HyperEVM `recipient`."*

For `ACTION_TRANSFER` (lines 120–122):
```solidity
if (action == ACTION_TRANSFER) {
    address recipient = abi.decode(tail, (address));
    _update(_systemAddress, recipient, amount);  // no guard: recipient can be address(this)
}
```
There is no check that `recipient != address(this)`.

For `ACTION_INIT_TRANSFER` (lines 123–135), the contract moves `amount` from `_systemAddress` to `address(this)`, then calls `OmniBridge.initTransfer(address(this), amount128, ...)`. `OmniBridge.initTransfer` (line 404–405) recognizes the token as a `BridgeToken` and calls `BridgeToken(tokenAddress).burn(msg.sender, amount)` — burning exactly `amount128`, not the full balance of `address(this)`. `BridgeToken.burn` (lines 62–64) calls `_burn(account, value)` for exactly `value`.

**Exploit sequence:**
1. HyperCore user A calls `sendToEvmWithData` with `data = 0x00 || abi.encode(tokenContractAddress)` and `amount = X`. The system address relays this, executing `_update(_systemAddress, address(this), X)`. The token contract now holds X tokens.
2. HyperCore user B calls `sendToEvmWithData` with `data = 0x01 || abi.encode(fee, recipient, message)` and `amount = Y` (Y ≠ X). The system address relays this, executing `_update(_systemAddress, address(this), Y)` (contract now holds X+Y), then `burn(address(this), Y)` (contract now holds X).

After both calls, X tokens are permanently locked in `HyperliquedBridgeToken`. There is no sweep, rescue, or admin-withdrawal function in either `HlBridgeToken` or `BridgeToken`. The only recovery path is a UUPS proxy upgrade.

## Impact Explanation

X tokens are permanently frozen at `address(this)` with no on-chain recovery mechanism. The HyperCore-side pool (`_systemAddress`) was debited X tokens, so the accounting drift is permanent: HyperCore believes X tokens were transferred to HyperEVM, but they are locked in the contract with no corresponding user credit. This constitutes a direct, irrecoverable permanent freezing of bridged funds — matching the Critical impact class: *"permanent freezing of bridged funds across NEAR, EVM, Solana, Starknet, Bitcoin, Zcash, or Wormhole-routed flows."*

## Likelihood Explanation

The only access gate is `msg.sender == _systemAddress`. The system address is a trusted relay that forwards whatever `data` a HyperCore user supplies via `sendToEvmWithData` — this is the explicit design of the contract per its NatSpec. Any HyperCore user can supply `recipient = tokenContractAddress` trivially, requiring no special privilege. The two calls need not be from the same user or in the same transaction. The exploit is repeatable and cumulative: each `ACTION_TRANSFER` with `recipient = address(this)` increases the stranded balance.

## Recommendation

Add a self-address guard in the `ACTION_TRANSFER` branch:

```solidity
if (action == ACTION_TRANSFER) {
    address recipient = abi.decode(tail, (address));
    require(recipient != address(this), "InvalidRecipient");
    _update(_systemAddress, recipient, amount);
}
```

Additionally, in `ACTION_INIT_TRANSFER`, burn the full balance of `address(this)` rather than exactly `amount128` to prevent any pre-existing balance from being silently stranded:

```solidity
uint128 contractBalance = balanceOf(address(this)).toUint128();
IOmniBridgeInitTransfer(owner()).initTransfer(address(this), contractBalance, fee, 0, recipient, message);
```

## Proof of Concept

```solidity
// Setup: HyperliquedBridgeToken deployed, _systemAddress seeded with 1500 tokens via 3-arg mint
// tokenAddress = address(token)

// Step 1: system address calls ACTION_TRANSFER with recipient = tokenAddress, amount = 500
bytes memory data1 = abi.encodePacked(uint8(0), abi.encode(tokenAddress));
vm.prank(systemAddress);
token.coreReceiveWithData(attacker, bytes32(0), 0, 500, 0, data1);
assertEq(token.balanceOf(tokenAddress), 500); // 500 tokens stranded in contract

// Step 2: system address calls ACTION_INIT_TRANSFER with amount = 1000
bytes memory data2 = abi.encodePacked(uint8(1), abi.encode(uint128(10), "near:alice.near", ""));
vm.prank(systemAddress);
token.coreReceiveWithData(attacker, bytes32(0), 0, 1000, 0, data2);
// OmniBridge.initTransfer burns exactly 1000 from tokenAddress
// token.balanceOf(tokenAddress) == 500  <-- permanently stranded
assertEq(token.balanceOf(tokenAddress), 500);
```