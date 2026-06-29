### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `init_transfer` - (File: `starknet/src/omni_bridge.cairo`)

### Summary
The Starknet `init_transfer` function transfers tokens from the caller into the bridge contract using the caller-supplied `amount`, then emits an `InitTransfer` event with that same `amount` — without verifying the actual balance received. If the token implements fee-on-transfer behavior, the bridge escrow receives fewer tokens than `amount`, but the NEAR hub processes the event and mints or unlocks the full `amount`, creating a permanent escrow deficit.

### Finding Description
In `starknet/src/omni_bridge.cairo`, the `init_transfer` function for non-bridge tokens executes:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
``` [1](#0-0) 

Immediately after, the event is emitted with the original caller-supplied `amount`:

```cairo
self.emit(Event::InitTransfer(InitTransfer {
    ...
    amount,
    ...
}))
``` [2](#0-1) 

No balance-before/after check is performed. The `assert(success, ...)` only confirms the call did not revert — it does not confirm the received amount equals `amount`. A fee-on-transfer token silently deducts a fee from the transferred amount, so `get_contract_address()` receives `amount - fee` while the event records `amount`.

The NEAR hub reads the emitted `amount` from the `InitTransfer` event and mints or unlocks that full value on the destination chain. The Starknet escrow is permanently underfunded by the fee amount per transfer.

The analogous EVM path (`OmniBridge.sol` `initTransfer`, lines 407–411) has the identical code pattern: [3](#0-2) 

However, `evm/SECURITY.md` explicitly classifies this as an intentional design decision and a documented non-issue:

> "Fee-on-transfer tokens not supported: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported." [4](#0-3) 

No equivalent acknowledgment exists in any Starknet-specific documentation. The Starknet `CLAUDE.md` lists "Transfer success validation for all external ERC20 calls" as a security property, but this refers only to revert-checking, not amount-received validation: [5](#0-4) 

There is no `SECURITY.md` for the Starknet component, and the `CLAUDE.md` does not mention fee-on-transfer or rebasing tokens anywhere.

### Impact Explanation
For every `init_transfer` call involving a fee-on-transfer token registered with the bridge:

- The Starknet bridge escrow receives `amount - fee` tokens.
- The NEAR hub mints or unlocks `amount` tokens on the destination chain.
- The deficit (`fee` per transfer) accumulates in the Starknet escrow.
- Eventually, legitimate withdrawals back to Starknet (`fin_transfer`) will fail or drain other users' funds because the escrow cannot cover the full committed amount.

This is a classic escrow mis-accounting leading to potential loss of bridged funds — matching the Critical impact category: "Balance manipulation, escrow mis-accounting… that changes user or protocol balances."

### Likelihood Explanation
The `init_transfer` function is fully public with no access control. Any caller can supply any `token_address`. A token deployer on Starknet can deploy a standard-looking ERC20 with a hidden transfer fee, get it registered with the bridge (the bridge is permissionless for token registration via `log_metadata`/`deploy_token`), and then initiate transfers. Alternatively, if a widely-used token (e.g., a future fee-enabled stablecoin) is registered, every ordinary user transfer silently creates a deficit. The likelihood is moderate: fee-on-transfer tokens are not the current Starknet norm, but the bridge's permissionless token registration makes the attack surface reachable by any unprivileged actor.

### Recommendation
Apply the same mitigation used in other bridge implementations: record the contract's token balance before and after the `transfer_from` call, and use the difference as the canonical `amount` for the emitted event:

```cairo
let balance_before = IERC20Dispatcher { contract_address: token_address }
    .balance_of(get_contract_address());
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
let balance_after = IERC20Dispatcher { contract_address: token_address }
    .balance_of(get_contract_address());
let actual_amount: u128 = (balance_after - balance_before).try_into().unwrap();
// use actual_amount in the emitted event, not amount
```

Alternatively, explicitly document fee-on-transfer and rebasing tokens as unsupported for Starknet (mirroring `evm/SECURITY.md` line 7) and enforce this at the token registration layer.

### Proof of Concept
1. Deploy a Starknet ERC20 token `FeeToken` that deducts 10% on every `transfer_from` call.
2. Register `FeeToken` with the Starknet bridge via `log_metadata`.
3. Call `init_transfer(token_address=FeeToken, amount=1000, fee=0, ...)`.
4. `transfer_from(caller, bridge, 1000)` executes; bridge receives 900 tokens (10% fee withheld).
5. `InitTransfer` event is emitted with `amount=1000`.
6. NEAR relayer processes the event; NEAR hub mints/unlocks 1000 tokens to the recipient.
7. Starknet escrow holds 900 tokens but is committed to 1000.
8. Repeat N times; after sufficient transfers, `fin_transfer` calls returning tokens to Starknet will fail due to insufficient escrow, freezing other users' funds. [6](#0-5)

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
```

**File:** evm/SECURITY.md (L7-7)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
```

**File:** starknet/CLAUDE.md (L53-53)
```markdown
- ✅ Reentrancy safe (CEI pattern + nonce check)
```
