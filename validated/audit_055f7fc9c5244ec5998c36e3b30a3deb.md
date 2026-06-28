### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.initTransfer` accepts any ERC-20 token via `safeTransferFrom` but emits the caller-supplied `amount` in the `InitTransfer` event rather than the actual tokens received. For fee-on-transfer tokens, the bridge holds fewer tokens than the event records. NEAR processes the event and credits the full `amount`, creating a permanent escrow deficit that grows with each such transfer and eventually prevents legitimate withdrawals.

### Finding Description
In `OmniBridge.initTransfer`, when the token is neither a bridge token nor a custom-minter token, the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not verified received amount
);
``` [1](#0-0) 

Immediately after, without any balance snapshot comparison, the contract emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← user-supplied, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

The `InitTransfer` event is the authoritative cross-chain message that NEAR (or Wormhole relayers) consume to credit the recipient. The `amount` field in `BridgeTypes.InitTransfer` is what NEAR mints or unlocks on the destination side. [3](#0-2) 

For `OmniBridgeWormhole`, the same unverified `amount` is also encoded directly into the Wormhole VAA payload:

```solidity
Borsh.encodeUint128(amount),   // ← same unverified value
``` [4](#0-3) 

If the ERC-20 token deducts a transfer fee, the bridge contract receives `amount - fee_amount` tokens, but the cross-chain message records `amount`. NEAR credits the user with `amount` tokens. The bridge's actual EVM-side escrow is now short by `fee_amount` per transfer.

### Impact Explanation
Each `initTransfer` call with a fee-on-transfer token inflates the NEAR-side accounting relative to the EVM-side escrow. When users later bridge back (triggering `finTransfer` on EVM), the bridge attempts to release the full recorded `amount`:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount   // ← inflated amount from NEAR record
);
``` [5](#0-4) 

The bridge will eventually be unable to honor withdrawals for the last users — their funds are permanently frozen in the bridge. This is a **Critical** escrow mis-accounting / permanent fund loss impact.

### Likelihood Explanation
The `initTransfer` function is fully permissionless and accepts any ERC-20 address in the `else` branch (no registry check on the token). Any user can call it with a fee-on-transfer token that has been registered via the permissionless `logMetadata`:

```solidity
function logMetadata(address tokenAddress) external payable {
``` [6](#0-5) 

Fee-on-transfer tokens exist on mainnet (e.g., USDT on some chains, STA, PAXG, tokens with dynamic fees). A user holding such a token can trigger this path without any special privilege. Likelihood is **Medium** (requires a fee-on-transfer token to be bridged, but the entry path is fully unprivileged and the `logMetadata` registration is permissionless).

### Recommendation
Capture the contract's token balance before and after the `safeTransferFrom` call, and use the delta as the authoritative `amount` for the event and cross-chain message:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived instead of amount in the event and extension call
```

Apply the same fix to the `amount` passed into `initTransferExtension` (and therefore into the Wormhole payload in `OmniBridgeWormhole`).

### Proof of Concept

1. Deploy or identify a mainnet ERC-20 token `FeeToken` that charges a 1% fee on every `transferFrom`.
2. Call `logMetadata(address(FeeToken))` — permissionless, no admin required.
3. Wait for NEAR to register the token metadata.
4. Call `OmniBridge.initTransfer(address(FeeToken), 1000e18, 0, 0, "alice.near", "")`.
   - `safeTransferFrom` moves `1000e18` from caller; bridge receives `990e18` (1% fee deducted).
   - `InitTransfer` event emits `amount = 1000e18`.
5. NEAR relayer observes the event and mints `1000e18` wrapped `FeeToken` to `alice.near`.
6. Alice bridges back: NEAR burns `1000e18` and signs a `finTransfer` for `1000e18`.
7. `finTransfer` on EVM calls `safeTransfer(alice, 1000e18)` but the bridge only holds `990e18` — the call reverts, Alice's funds are permanently frozen.

Repeating step 4 many times with many users accelerates the deficit until the bridge is fully insolvent for `FeeToken`.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-231)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
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

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L23-32)
```text
    event InitTransfer(
        address indexed sender,
        address indexed tokenAddress,
        uint64 indexed originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string recipient,
        string message
    );
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L129-141)
```text
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
```
