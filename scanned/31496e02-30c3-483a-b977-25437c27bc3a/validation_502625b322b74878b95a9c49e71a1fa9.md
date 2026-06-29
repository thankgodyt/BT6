### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` Allows Draining of Bridge Reserves - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol::initTransfer` records the caller-supplied `amount` in the `InitTransfer` event without verifying the actual number of tokens received by the contract. When a fee-on-transfer ERC20 token is used, the bridge holds `amount − transfer_fee` tokens but the event—which is the sole source of truth for the NEAR prover—asserts `amount`. NEAR then mints or releases `amount` bridge tokens, permanently over-issuing relative to the EVM escrow. Repeated transfers drain the bridge's reserves, causing loss of funds for honest users.

---

### Finding Description

In `initTransfer`, for the standard ERC20 (non-bridge-token, non-custom-minter) path, the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // ← requested amount, not verified received amount
);
``` [1](#0-0) 

Immediately after, without any balance-before/after check, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← same caller-supplied value, not actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

The `InitTransfer` event is explicitly documented as the sole source of truth for the NEAR prover:

> "The `InitTransfer` event must contain all data required for the NEAR side to reconstruct the transfer, as it is the sole source of truth for provers."

The NEAR `omni-bridge` contract's `fin_transfer` path uses the proven `amount` field directly to unlock or mint tokens on NEAR, with no independent verification of what the EVM bridge actually holds.

The identical pattern exists in the Starknet bridge:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
// ... emits InitTransfer with `amount` unchanged
``` [3](#0-2) [4](#0-3) 

---

### Impact Explanation

For an EVM-native token with a transfer fee of `f` basis points:

1. User calls `initTransfer(token, amount, ...)` → bridge receives `amount × (1 − f)`, event records `amount`.
2. NEAR prover verifies the event and mints `amount` bridge-wrapped tokens to the recipient.
3. The recipient bridges back: NEAR burns `amount` bridge tokens; EVM `finTransfer` attempts `safeTransfer(recipient, amount)`.
4. The bridge only holds `amount × (1 − f)` of the native token → the `safeTransfer` either reverts (blocking the withdrawal) or, if multiple users have deposited, silently drains other users' deposits.

The `locked_tokens` accounting on NEAR is also corrupted: `lock_tokens_if_needed` credits the full `amount` against the chain's escrow counter, but the actual EVM balance is short by `amount × f` per transfer. [5](#0-4) 

The cumulative shortfall grows with every `initTransfer` call using a fee-on-transfer token, eventually making the bridge insolvent for that token.

---

### Likelihood Explanation

The bridge is permissionless for any ERC20 token that has been registered via `logMetadata`. Fee-on-transfer tokens are a well-known ERC20 variant (USDT has a dormant fee switch; tokens like STA, PAXG, and others actively charge fees). An attacker can:

- Use an existing fee-on-transfer token already registered with the bridge, or
- Deploy a token with a fee mechanism through any supported factory path and register it.

No admin compromise, key leak, or validator collusion is required. The attacker only needs to call the public `initTransfer` function. [6](#0-5) 

---

### Recommendation

Replace the static `amount` in the `InitTransfer` event with the actual received amount, measured by a balance-before/after check:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint128 actualReceived = (IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore).toUint128();

emit BridgeTypes.InitTransfer(
    msg.sender, tokenAddress, currentOriginNonce,
    actualReceived, fee, nativeFee, recipient, message
);
```

Apply the same fix to `starknet/src/omni_bridge.cairo::init_transfer`. Additionally, document that fee-on-transfer and rebasing tokens are unsupported until this is addressed.

---

### Proof of Concept

1. Deploy a standard ERC20 token `FeeToken` that deducts a 1% fee on every `transferFrom`, keeping the fee in a treasury address.
2. Register `FeeToken` with the bridge via `logMetadata`.
3. Approve the bridge for `1000` tokens and call `initTransfer(FeeToken, 1000, 0, 0, "alice.near", "")`.
4. Bridge receives `990` tokens (`balanceOf(bridge)` increases by 990), but the `InitTransfer` event records `amount = 1000`.
5. A relayer submits the Ethereum receipt proof to NEAR `fin_transfer`; NEAR mints `1000` bridge-FeeToken to `alice.near`.
6. Alice calls `ft_transfer_call` on NEAR to bridge back `1000` tokens to Ethereum.
7. NEAR burns `1000` bridge-FeeToken and emits a signed payload for `1000` native tokens.
8. The EVM `finTransfer` attempts `safeTransfer(alice_evm, 1000)` but the bridge only holds `990` → the transfer reverts, permanently locking Alice's funds, or drains 10 tokens from another depositor's balance. [7](#0-6) [2](#0-1)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-380)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
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

**File:** near/omni-bridge/src/token_lock.rs (L48-68)
```rust
    fn lock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        let new_amount = current_amount
            .checked_add(amount)
            .near_expect(TokenLockError::LockedTokensOverflow);

        self.locked_tokens.insert(&key, &new_amount);

        LockAction::Locked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
```
