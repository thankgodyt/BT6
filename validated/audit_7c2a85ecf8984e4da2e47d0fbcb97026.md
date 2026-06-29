Audit Report

## Title
`nativeFee` ETH Permanently Locked With No Distribution or Recovery Path — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

## Summary

In `OmniBridge.initTransfer`, the ETH corresponding to `nativeFee` is subtracted from `msg.value` to produce `extensionValue`, but is never forwarded to any relayer, fee recipient, or external contract. It accumulates in the `OmniBridge` contract indefinitely. No withdrawal, sweep, or distribution function exists anywhere in the contract, making every wei of `nativeFee` ETH irrecoverable.

## Finding Description

`initTransfer` computes `extensionValue` by excluding `nativeFee` from `msg.value`:

- ETH path: `extensionValue = msg.value - amount - nativeFee` [1](#0-0) 
- ERC20 path: `extensionValue = msg.value - nativeFee` [2](#0-1) 

Only `extensionValue` is passed to `initTransferExtension`. [3](#0-2) 

In `OmniBridgeWormhole`, `initTransferExtension` forwards exactly `value` (i.e., `extensionValue`) to Wormhole: `_wormhole.publishMessage{value: value}(...)`. [4](#0-3) 

`nativeFee` is encoded into the Wormhole payload as a `uint128` field, so the NEAR side receives the *value* of `nativeFee` as a number, but the corresponding ETH never leaves the EVM contract. There is no on-chain mechanism to route it to a relayer address, no admin `withdrawFees` function, and no guarded sweep. The contract does have a bare `receive()` fallback, which allows ETH to enter but provides no exit path. [5](#0-4) 

A full search of `OmniBridge.sol` and `OmniBridgeWormhole.sol` confirms there is no function that transfers ETH out of the contract except `finTransfer`'s recipient payout for ETH bridge-back flows — a completely separate accounting pool. [6](#0-5) 

## Impact Explanation

Every call to `initTransfer` or `initTransfer1155` with `nativeFee > 0` causes a permanent, irrecoverable loss of that ETH from the caller. This is direct fee mis-accounting: the user's balance decreases by `nativeFee`, the contract's balance increases by `nativeFee`, and no relayer or protocol address ever receives it. This matches the allowed Critical impact: **fee mis-accounting that changes user or protocol balances**.

## Likelihood Explanation

`nativeFee` is a first-class parameter of the public `initTransfer` interface, present precisely to incentivize relayers to process EVM→NEAR transfers. Any user who wants timely processing will set it to a non-zero value. There is no input validation rejecting `nativeFee > 0`, no documentation warning against it, and the Wormhole message encodes the value — implying the NEAR side expects it. This is a normal, expected usage path reachable by any unprivileged external caller with no special preconditions.

## Recommendation

The ETH corresponding to `nativeFee` must be explicitly routed at the time of `initTransfer`. Two concrete options:

1. **Forward `nativeFee` to a designated relayer vault or fee recipient address** immediately inside `initTransfer`, before or after calling `initTransferExtension`.
2. **Revert if `msg.value` does not exactly equal `extensionValue + amount` (ETH) or `extensionValue + nativeFee` (ERC20)**, so no unaccounted ETH can enter the contract. If `nativeFee` is intended to be denominated in NEAR (not ETH), the parameter should not consume any `msg.value` at all and the subtraction should be removed.

Additionally, add a guarded `withdrawFees(address recipient)` function restricted to `DEFAULT_ADMIN_ROLE` as a safety net for any ETH that accumulates from edge cases.

## Proof of Concept

1. Deploy `OmniBridgeWormhole` on a local testnet with a mock Wormhole that charges 0 message fee.
2. Call `initTransfer(address(0), 1 ether, 0, 0.01 ether, "recipient.near", "")` with `msg.value = 1.01 ether`.
3. Observe: `extensionValue = 1.01 ether - 1 ether - 0.01 ether = 0`. Wormhole receives 0 ETH. The `InitTransfer` event is emitted with `nativeFee = 0.01 ether`.
4. Check `address(omniBridge).balance` — it holds `0.01 ether`.
5. Attempt to call any function to recover the `0.01 ether` — none exists. The ETH is permanently locked.
6. Repeat N times; the locked balance grows linearly with no bound and no recovery path.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L391-391)
```text
            extensionValue = msg.value - amount - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L393-393)
```text
            extensionValue = msg.value - nativeFee;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-425)
```text
        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L574-574)
```text
    receive() external payable {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L143-147)
```text
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );
```
