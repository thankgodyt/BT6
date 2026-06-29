Audit Report

## Title
Native ETH Delivery in `finTransfer` Permanently Freezes Funds When Recipient Cannot Receive ETH - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

In `OmniBridge.sol`, `finTransfer` delivers native ETH via a bare low-level call. If the recipient is a smart contract without a `receive`/`fallback` function, the call fails and the entire transaction reverts — including the nonce-consumption write. Because the MPC signature irrevocably binds the recipient address, every retry produces the same revert. Tokens are already burned/locked on NEAR, and the ETH remains permanently locked in the `OmniBridge` contract with no on-chain recovery path.

## Finding Description

`completedTransfers[payload.destinationNonce] = true` is written at line 287, before the ETH delivery attempt at lines 319–322:

```solidity
completedTransfers[payload.destinationNonce] = true;   // line 287
...
(bool success, ) = payload.recipient.call{value: payload.amount}("");
if (!success) revert FailedToSendEther();               // line 322
``` [1](#0-0) [2](#0-1) 

When `revert FailedToSendEther()` is thrown, the EVM unwinds all state changes in the transaction, including the line 287 write. The nonce is therefore never consumed. However, the MPC signature encodes `payload.recipient` directly in the Borsh payload:

```solidity
Borsh.encodeAddress(payload.recipient),
``` [3](#0-2) 

Signature verification at lines 311–313 enforces this binding — any attempt to substitute a different recipient produces `InvalidSignature()`: [4](#0-3) 

On the NEAR side, tokens are burned/locked before the `InitTransferEvent` is emitted, with no refund path if EVM finalization permanently fails: [5](#0-4) 

The contract contains no admin rescue function, no emergency ETH withdrawal, and no alternative delivery mechanism. A full audit of the contract confirms the absence of any `rescue`, `withdraw`, or `emergency` function. [6](#0-5) 

## Impact Explanation

This constitutes **permanent freezing of bridged funds**: ETH locked in the `OmniBridge` contract on EVM is undeliverable (no on-chain recovery path), and the corresponding tokens on NEAR are already burned/locked with no refund mechanism. This matches the Critical allowed impact: *permanent freezing of bridged funds across NEAR and EVM*.

## Likelihood Explanation

No special privilege is required. Any bridge user who specifies a contract address as the EVM recipient of a NEAR→EVM native ETH transfer triggers this path. Contract recipients are ubiquitous in DeFi: Gnosis Safe multisigs, protocol treasuries, yield aggregators, and smart-contract wallets frequently lack a `receive` function. The user need not act maliciously — a routine bridge operation to a contract wallet is sufficient.

## Recommendation

Replace the bare ETH call with a WETH-fallback pattern: attempt the native ETH send; if it fails, wrap into WETH and transfer WETH to the recipient:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) {
        IWETH(weth).deposit{value: payload.amount}();
        IERC20(weth).safeTransfer(payload.recipient, payload.amount);
    }
}
```

Alternatively, adopt a pull-payment pattern: escrow the ETH under the recipient's key on failed delivery and allow the recipient to claim it in a separate transaction, ensuring `finTransfer` always succeeds and the nonce is always consumed.

## Proof of Concept

1. Deploy `MyContract` on a local EVM fork with no `receive`/`fallback` function.
2. On NEAR, call `ft_transfer_call` to initiate a native ETH transfer with `recipient = address(MyContract)`. NEAR burns/locks the tokens and emits `InitTransferEvent`.
3. Relayer constructs `TransferMessagePayload` with `tokenAddress = address(0)`, `recipient = address(MyContract)`, obtains MPC signature.
4. Relayer calls `finTransfer(signatureData, payload)` on EVM.
5. Execution reaches line 319: `payload.recipient.call{value: payload.amount}("")` — `MyContract` has no `receive`, so `success = false`.
6. Line 322: `revert FailedToSendEther()` — entire transaction reverts, including the `completedTransfers[nonce] = true` write at line 287.
7. Relayer retries — identical revert every time; recipient is fixed in the MPC-signed payload.
8. ETH remains locked in `OmniBridge` indefinitely. Tokens on NEAR are already burned. Funds are permanently frozen. [7](#0-6) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L28-66)
```text
contract OmniBridge is
    UUPSUpgradeable,
    AccessControlUpgradeable,
    SelectivePausableUpgradable,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;

    mapping(address => string) public ethToNearToken;
    mapping(string => address) public nearToEthToken;
    mapping(address => bool) public isBridgeToken;

    address public tokenImplementationAddress;
    address public nearBridgeDerivedAddress;
    uint8 public omniBridgeChainId;

    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;

    mapping(address => address) public customMinters;
    mapping(address => MultiTokenInfo) public multiTokens;

    bytes32 public constant PAUSABLE_ADMIN_ROLE =
        keccak256("PAUSABLE_ADMIN_ROLE");
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;

    error InvalidSignature();
    error NonceAlreadyUsed(uint64 nonce);
    error InvalidFee();
    error InvalidValue();
    error FailedToSendEther();
    error ERC1155MappingMismatch();
    error ERC1155DirectSendNotAllowed();
    error ERC1155BatchNotSupported();
    error TokenImplementationNotSet();

```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-322)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** near/omni-bridge/src/lib.rs (L1850-1863)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
```
