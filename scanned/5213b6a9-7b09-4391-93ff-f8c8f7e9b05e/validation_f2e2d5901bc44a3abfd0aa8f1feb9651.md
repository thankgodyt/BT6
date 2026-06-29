### Title
Fee-on-Transfer Token Mis-Accounting in `initTransfer` Causes Vault Drain — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` uses the caller-supplied `amount` parameter both to pull tokens via `safeTransferFrom` and to emit the `InitTransfer` event. For fee-on-transfer ERC20 tokens, the vault receives fewer tokens than `amount`, but the cross-chain message records the full `amount`. When the transfer is finalized on the destination chain, the full `amount` is released from the vault (or minted), permanently draining the bridge's reserves.

---

### Finding Description

In `OmniBridge.initTransfer`, the native-token branch (i.e., tokens that are neither bridge tokens nor custom-minter tokens) executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied; actual received may be less
);
```

Immediately after, without any balance check, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // still the caller-supplied value, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
```

The NEAR bridge indexer reads this event and constructs a `TransferMessage` carrying the inflated `amount`. When `finTransfer` is later called on the EVM side (or any destination chain), it releases `payload.amount` tokens from the vault:

```solidity
IERC20(payload.tokenAddress).safeTransfer(
    payload.recipient,
    payload.amount   // inflated amount, not what was actually locked
);
```

No pre/post balance check is performed anywhere in the flow to reconcile the actual deposited amount against the recorded amount.

The same pattern exists in `starknet/src/omni_bridge.cairo` `init_transfer`, where `transfer_from` is called with `amount` and the same `amount` is emitted in the `InitTransfer` event without a balance delta check.

---

### Impact Explanation

For every `initTransfer` call with a fee-on-transfer token (e.g., STA, PAXG, or future USDC/USDT with fees enabled):

- The vault receives `amount * (1 - fee_rate)` tokens.
- The cross-chain message records `amount` tokens.
- On finalization, `amount` tokens are released from the vault.
- The shortfall (`amount * fee_rate`) is taken from other users' deposits.

Repeated calls drain the vault proportionally to the token's transfer fee. An attacker can deliberately exploit this by repeatedly bridging a fee-on-transfer token, extracting the fee-rate fraction of the vault's reserves on each round trip. This constitutes a direct, permanent loss of bridged funds held in the EVM vault.

---

### Likelihood Explanation

Any unprivileged user can call `initTransfer` with any ERC20 token address. There is no whitelist restricting which tokens may be bridged. Fee-on-transfer tokens are a known, deployed token class on mainnet. The attacker only needs to hold a small amount of such a token and call `initTransfer` repeatedly. No admin compromise, key leak, or external dependency failure is required.

---

### Recommendation

After the `safeTransferFrom` call, measure the actual received amount using a pre/post balance check and use that value for the emitted event and cross-chain message:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived instead of amount in the event and downstream logic
```

Alternatively, maintain a token whitelist that restricts bridgeable tokens to those without transfer fees.

---

### Proof of Concept

1. Deploy or use a mainnet fee-on-transfer ERC20 token `FOT` with a 10% transfer fee.
2. Approve `OmniBridge` to spend 100 `FOT`.
3. Call `OmniBridge.initTransfer(FOT, 100, 0, 0, "attacker.near", "")`.
4. `safeTransferFrom` pulls 100 `FOT` from the caller; the token's internal fee logic deducts 10, so `address(this)` receives only 90 `FOT`.
5. The `InitTransfer` event emits `amount = 100`.
6. The NEAR indexer picks up the event and issues a `finTransfer` proof for 100 `FOT`.
7. On `finTransfer` execution, `safeTransfer(attacker_evm, 100)` is called, releasing 100 `FOT` from the vault — 10 more than were deposited.
8. Repeat to drain the vault at a rate of 10 `FOT` per 100 bridged.

**Relevant code locations:**

`safeTransferFrom` with caller-supplied `amount` (no post-balance check): [1](#0-0) 

`InitTransfer` event emitted with the same caller-supplied `amount`: [2](#0-1) 

`finTransfer` releasing `payload.amount` (the inflated value) from the vault: [3](#0-2) 

Same pattern on Starknet — `transfer_from` with `amount`, then event emits `amount` without balance delta: [4](#0-3) [5](#0-4)

### Citations

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

**File:** starknet/src/omni_bridge.cairo (L304-306)
```text
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
```

**File:** starknet/src/omni_bridge.cairo (L316-330)
```text
            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```
