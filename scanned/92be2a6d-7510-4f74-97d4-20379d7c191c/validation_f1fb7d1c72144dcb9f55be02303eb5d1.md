### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` transfers a caller-specified `amount` of any arbitrary ERC-20 token into the bridge escrow using `safeTransferFrom`, then unconditionally emits `InitTransfer` with that same `amount`. For fee-on-transfer tokens the bridge actually receives `amount − fee_taken`, yet the NEAR side observes `amount` in the event and mints the full `amount` to the recipient. The escrow is permanently under-collateralised by the fee delta on every such deposit, enabling an attacker to extract more value from the bridge than was ever locked.

---

### Finding Description

`logMetadata` is a permissionless, payable function with no access control: [1](#0-0) 

Any caller can register any ERC-20 token — including fee-on-transfer tokens — with the NEAR side of the bridge by emitting a `LogMetadata` event.

Once registered, `initTransfer` accepts that token. In the "plain ERC-20" branch (lines 406–411) the bridge calls:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not actual received amount
);
``` [2](#0-1) 

No balance snapshot is taken before or after the call. The function then emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← always the requested amount
    ...
);
``` [3](#0-2) 

The `InitTransfer` event is the authoritative signal consumed by the NEAR bridge to mint wrapped tokens. Its `amount` field is defined in `BridgeTypes`: [4](#0-3) 

For a fee-on-transfer token with a transfer tax of `t%`, the bridge holds `amount × (1 − t/100)` but the NEAR side mints `amount`. The gap is `amount × t/100` per deposit — real tokens that were never locked but will be claimed on redemption.

On the `finTransfer` redemption path the bridge releases the full `payload.amount` from its reserves: [5](#0-4) 

Each round-trip therefore drains `amount × t/100` tokens from the bridge's aggregate reserves for that token, eventually making the bridge insolvent for all holders of that wrapped asset.

---

### Impact Explanation

**Critical — escrow mis-accounting / permanent loss of bridged funds.**

The bridge locks less than it credits. After enough round-trips the bridge cannot honour redemptions for honest users who deposited standard (non-fee) amounts of the same token, or the bridge's entire reserve for that token is exhausted. This is a direct, quantifiable loss of bridged funds, matching the "balance manipulation, escrow mis-accounting" category in the allowed impact scope.

---

### Likelihood Explanation

**Medium.** The attacker only needs to:
1. Deploy or use an existing fee-on-transfer ERC-20 token.
2. Call the permissionless `logMetadata` to register it (no ETH cost in the base `OmniBridge`; a small Wormhole fee in `OmniBridgeWormhole`).
3. Repeatedly call `initTransfer` / bridge back to drain the reserve.

No admin interaction, no private key, no oracle manipulation, and no threshold-signature compromise is required. The entry path is fully unprivileged.

---

### Recommendation

Measure the actual received amount by snapshotting the bridge's balance before and after `safeTransferFrom`, and use the delta — not the caller-supplied `amount` — in the emitted event and in all downstream accounting:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived in the event and in initTransferExtension
```

Apply the same pattern to the `customMinters` branch where `safeTransferFrom` targets the minter address.

---

### Proof of Concept

1. **Deploy** `FeeToken` — a standard ERC-20 that deducts 5% on every `transferFrom` (keeps 95% of `amount`).
2. **Register** the token: call `OmniBridge.logMetadata(address(FeeToken))`. No permission required.
3. **Wait** for the NEAR relayer to process the `LogMetadata` event and register the wrapped asset.
4. **Deposit**: call `OmniBridge.initTransfer(address(FeeToken), 1_000e18, 0, 0, "near:attacker.near", "")`.
   - `safeTransferFrom` moves `1_000e18` from attacker; bridge receives `950e18` (5% fee taken by token).
   - `InitTransfer` event emits `amount = 1_000e18`.
   - NEAR mints `1_000e18` wrapped tokens to `attacker.near`.
5. **Redeem**: attacker bridges back `1_000e18` wrapped tokens from NEAR.
   - NEAR burns `1_000e18`; MPC signs a `finTransfer` payload with `amount = 1_000e18`.
   - Bridge calls `safeTransfer(attacker, 1_000e18)` — releases `1_000e18` from its `950e18` reserve.
   - If the bridge has other depositors' funds, `50e18` is silently taken from them; if not, the call reverts (DoS for all redeemers).
6. **Repeat** steps 4–5 to drain the bridge's entire reserve for `FeeToken` (and, via reserve sharing, any co-mingled balance).

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-355)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

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
