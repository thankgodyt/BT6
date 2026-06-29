### Title
Fee-on-Transfer Token Mis-Accounting in `initTransfer` Emits Inflated Amount, Enabling Over-Minting on NEAR - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The `initTransfer` function in `OmniBridge.sol` emits the caller-supplied `amount` parameter in the `InitTransfer` event rather than the actual tokens received by the contract. For fee-on-transfer ERC20 tokens, the contract locks fewer tokens than the event claims, causing the NEAR side to mint or unlock more tokens than are held in escrow on EVM — permanently undercollateralizing the bridge vault.

---

### Finding Description

In `OmniBridge.sol`, the non-bridge, non-custom ERC20 token path of `initTransfer` performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not actual received
);
```

Immediately after, the event is emitted using the same `amount` parameter:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // ← parameter value, not balance delta
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) [2](#0-1) 

The NEAR side's entire trust model for inbound EVM transfers is built on the `InitTransfer` event — it is the **only** data the NEAR contract sees, as documented explicitly in the EVM architecture notes:

> "Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees." [3](#0-2) 

The NEAR bridge contract parses this event (via `near/omni-types/src/evm/events.rs`) and uses the `amount` field directly to determine how many tokens to mint or unlock for the recipient. [4](#0-3) 

For a fee-on-transfer token, `safeTransferFrom(..., amount)` causes the contract to receive `amount - transfer_fee` tokens, but the event records `amount`. The NEAR side then mints/unlocks `amount` tokens — more than the EVM vault holds.

The same root cause exists in the Starknet contract: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

Each `initTransfer` call with a fee-on-transfer token creates a deficit equal to the transfer fee. Over multiple transfers, the EVM vault becomes progressively undercollateralized. When users later bridge tokens back from NEAR to EVM (via `finTransfer`), the contract cannot fulfill all redemptions — some users permanently lose funds. This is a direct **escrow mis-accounting** leading to **loss of bridged funds**.

---

### Likelihood Explanation

`initTransfer` is a public, permissionless function callable by any token holder. No special role or privilege is required. Any user who initiates a bridge transfer with a fee-on-transfer ERC20 token (e.g., tokens with deflationary mechanics, STA, PAXG, etc.) triggers the bug. The attacker does not need to be malicious — even honest users cause the deficit. A malicious actor can deliberately amplify the deficit by repeatedly bridging small amounts of a fee-on-transfer token.

---

### Recommendation

Replace the use of the `amount` parameter in the emitted event with the actual balance delta. Before and after the `safeTransferFrom` call, snapshot the contract's token balance and use the difference as the authoritative locked amount:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// Use actualReceived (cast to uint128) in the event and downstream logic
```

Apply the same fix to the Starknet `init_transfer` function in `starknet/src/omni_bridge.cairo`.

---

### Proof of Concept

1. Deploy or use any ERC20 token that charges a 1% transfer fee on every `transferFrom`.
2. Call `OmniBridge.initTransfer(feeToken, 1000, 0, 0, "alice.near", "")`.
3. The contract receives `990` tokens (1% fee deducted by the token).
4. The `InitTransfer` event is emitted with `amount = 1000`.
5. The NEAR relayer picks up the event and calls `fin_transfer` on NEAR, which mints `1000` tokens to `alice.near`.
6. The EVM vault now holds `990` tokens but has issued a claim for `1000` — a deficit of `10` tokens per transfer.
7. After 100 such transfers, the vault is short `1000` tokens. The last ~10 users to bridge back from NEAR to EVM cannot redeem their tokens.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-412)
```text
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
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

**File:** evm/CLAUDE.md (L23-23)
```markdown
**EVM → NEAR (initTransfer)**: User calls `initTransfer` which burns/locks tokens on EVM and emits `InitTransfer` with all transfer details (sender, token, amount, fee, nativeFee, recipient, message). In the Wormhole variant, a Wormhole message is also sent. The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees.
```

**File:** near/omni-types/src/evm/events.rs (L12-21)
```rust
    event InitTransfer(
        address indexed sender,
        address indexed tokenAddress,
        uint64 indexed originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeTokenFee,
        string recipient,
        string message
    );
```

**File:** starknet/src/omni_bridge.cairo (L303-306)
```text
            } else {
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
