### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` uses the caller-supplied `amount` parameter in the emitted `InitTransfer` event rather than the actual tokens received by the contract. For fee-on-transfer ERC20 tokens, the contract receives `amount - transfer_fee` but emits `amount`. The NEAR side treats the emitted event as authoritative proof of the locked amount and mints the full `amount` to the recipient, permanently undercollateralizing the EVM escrow.

### Finding Description

In `OmniBridge.initTransfer`, when the token is a plain ERC20 (not a bridge token and not a custom minter), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not actual received
);
``` [1](#0-0) 

Immediately after, the event is emitted using the original `amount` parameter:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← caller-supplied, not balance-delta
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

For a fee-on-transfer token, `safeTransferFrom` deducts a fee at the token level, so the bridge contract receives `amount - token_fee` while the event records `amount`. The NEAR bridge reads this event as the sole source of truth for how many tokens are locked on EVM:

> "The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees." [3](#0-2) 

The NEAR contract then mints or unlocks `amount` tokens for the recipient, while the EVM contract only holds `amount - token_fee`. The same pattern exists in the Starknet bridge:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
// ...
self.emit(Event::InitTransfer(InitTransfer { ..., amount, ... }))
``` [4](#0-3) 

### Impact Explanation

Each `initTransfer` call with a fee-on-transfer token creates a deficit of `token_fee` tokens in the EVM escrow. NEAR mints the full `amount` to the recipient. When those NEAR-side tokens are later bridged back via `finTransfer`, the EVM contract must release `amount` tokens but only holds `amount - token_fee`. Repeated bridging drains the escrow, causing `finTransfer` calls to fail for legitimate users — permanent freezing of bridged funds. The protocol's own invariant is violated:

> "Event–transfer atomicity: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction … the NEAR side will treat any emitted event as proof that tokens are held." [5](#0-4) 

### Likelihood Explanation

Fee-on-transfer ERC20 tokens exist in production (e.g., tokens with redistribution mechanics, tax tokens). The `initTransfer` function has no whitelist check — any ERC20 address is accepted. A token can also add a transfer fee after being registered with the bridge. An unprivileged user only needs to call `initTransfer` with such a token; no special role or privilege is required.

### Recommendation

Measure the actual received amount using a balance-before/after pattern:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(actualReceived == amount, "FeeOnTransferNotSupported");
```

Either revert on any discrepancy (rejecting fee-on-transfer tokens entirely) or use `actualReceived` as the emitted `amount`. The same fix must be applied to `starknet/src/omni_bridge.cairo`'s `init_transfer`.

### Proof of Concept

1. A fee-on-transfer ERC20 token `FTT` with a 1% transfer fee is registered with the bridge (or a registered token adds a fee post-registration).
2. Attacker calls `OmniBridge.initTransfer(FTT, 1000, 0, 0, "attacker.near", "")`.
3. `safeTransferFrom` transfers 1000 from attacker; FTT deducts 1% fee → bridge receives 990.
4. `InitTransfer` event emits `amount = 1000`.
5. NEAR light client/prover reads the event; NEAR bridge mints 1000 FTT-equivalent tokens to `attacker.near`.
6. Attacker now holds 1000 NEAR-side tokens backed by only 990 EVM-side tokens.
7. Attacker bridges 1000 tokens back: `finTransfer` on EVM attempts `safeTransfer(attacker, 1000)` but contract only holds 990 → reverts, or drains reserves of other depositors. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-436)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

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

**File:** evm/CLAUDE.md (L36-36)
```markdown
- **Event–transfer atomicity**: `InitTransfer` must only be emitted in a code path where tokens have already been burned/locked in the same transaction. If the token transfer reverts or is skipped, the event must not emit — the NEAR side will treat any emitted event as proof that tokens are held
```

**File:** starknet/src/omni_bridge.cairo (L281-331)
```text
        fn init_transfer(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u128,
            fee: u128,
            native_fee: u128,
            recipient: ByteArray,
            message: ByteArray,
        ) {
            assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

            assert(amount > 0, 'ERR_ZERO_AMOUNT');
            assert(fee < amount, 'ERR_INVALID_FEE');

            let origin_nonce = self.current_origin_nonce.read() + 1;
            self.current_origin_nonce.write(origin_nonce);

            let caller = get_caller_address();

            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

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
        }
```
