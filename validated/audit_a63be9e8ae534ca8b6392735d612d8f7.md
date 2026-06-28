### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `init_transfer` - (File: `starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge.init_transfer` function transfers `amount` tokens from the caller into the contract's escrow, then emits an `InitTransfer` event with that same `amount`. NEAR processes this event and mints `amount` tokens on the destination chain. For fee-on-transfer tokens, the contract actually receives `amount - transfer_fee`, but the event (and therefore the NEAR-side mint) uses the full `amount`. This creates an underfunded escrow: more tokens are minted on NEAR than are locked on Starknet, enabling permanent loss of funds for later bridge users.

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function for non-bridge tokens performs:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
``` [1](#0-0) 

It then emits the event with the caller-supplied `amount`:

```cairo
self.emit(Event::InitTransfer(InitTransfer {
    ...
    amount,
    ...
}));
``` [2](#0-1) 

The code never measures the actual balance delta (balance after − balance before). For a fee-on-transfer token, `transfer_from` succeeds and returns `true`, but the contract receives only `amount - transfer_fee`. The emitted `amount` is the full requested value.

NEAR's `fin_transfer_callback` reads the `InitTransfer` event's `amount` field directly and uses it to mint or release tokens on the destination chain: [3](#0-2) 

The `denormalize_amount` applied there operates on the event-reported `amount`, not the actual locked amount: [4](#0-3) 

The EVM `SECURITY.md` explicitly acknowledges fee-on-transfer tokens as an intentional non-issue for the EVM bridge: [5](#0-4) 

No equivalent acknowledgment exists in `starknet/CLAUDE.md` or any Starknet-specific security note. The Starknet CLAUDE.md lists "Transfer success validation for all external ERC20 calls" as a security property, but does not address the balance-delta gap: [6](#0-5) 

### Impact Explanation

An attacker deploys a fee-on-transfer token on Starknet, calls the permissionless `log_metadata`, waits for NEAR to deploy the corresponding token, then calls `init_transfer`. The Starknet escrow receives `amount - fee` but NEAR mints `amount`. The attacker bridges back `amount` tokens from NEAR to Starknet, draining the escrow by `fee` tokens per round trip. Repeated exploitation or concurrent legitimate users of the same token will cause the Starknet contract to have insufficient balance, permanently freezing the last users' funds. This is a critical escrow mis-accounting issue: the total supply of the token on NEAR exceeds the total locked on Starknet.

### Likelihood Explanation

`log_metadata` on Starknet is explicitly permissionless: [7](#0-6) 

Any unprivileged attacker can deploy a fee-on-transfer token, register it with the bridge, and exploit this path. No admin access or key compromise is required. The `init_transfer` function has no token whitelist: [8](#0-7) 

### Recommendation

Measure the actual received amount using a balance-before/balance-after check:

```cairo
let balance_before = IERC20Dispatcher { contract_address: token_address }
    .balance_of(get_contract_address());
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
assert(success, 'ERR_TRANSFER_FROM_FAILED');
let balance_after = IERC20Dispatcher { contract_address: token_address }
    .balance_of(get_contract_address());
let actual_received: u128 = (balance_after - balance_before).try_into().unwrap();
// Use actual_received in the emitted event instead of amount
```

Alternatively, maintain a token whitelist so only known-safe tokens (no fee-on-transfer, no rebasing) can be bridged via Starknet, consistent with the EVM bridge's documented design decision.

### Proof of Concept

1. Attacker deploys `FeeToken` on Starknet: a standard ERC20 that deducts 10% on every `transfer_from` call, returning `true`.
2. Attacker calls `starknet_bridge.log_metadata(fee_token_address)` — permissionless, succeeds.
3. NEAR relayer processes the `LogMetadata` event and calls `deploy_token` on NEAR, creating `fee_token.near`.
4. Attacker calls `starknet_bridge.init_transfer(fee_token_address, 1000, 0, 0, "near:attacker.near", "")`.
   - `transfer_from` moves 1000 tokens; contract receives 900 (10% fee deducted).
   - `InitTransfer` event emits `amount = 1000`.
5. NEAR relayer submits proof; `fin_transfer_callback` mints 1000 `fee_token.near` to `attacker.near`.
6. Attacker calls NEAR `init_transfer` to bridge 1000 `fee_token.near` back to Starknet.
7. NEAR burns 1000 tokens; Starknet `fin_transfer` tries to release 1000 tokens — but only 900 are in escrow.
8. If another legitimate user had also deposited 900 tokens (receiving 1000 on NEAR), the Starknet escrow now holds 1800 but owes 2000. The last user's `fin_transfer` reverts; their funds are permanently frozen. [9](#0-8) [10](#0-9)

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

**File:** near/omni-bridge/src/lib.rs (L705-732)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };
```

**File:** near/omni-bridge/src/lib.rs (L2776-2779)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }
```

**File:** evm/SECURITY.md (L7-7)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
```

**File:** starknet/CLAUDE.md (L19-19)
```markdown
| `log_metadata` | Log token metadata for indexers | Public |
```

**File:** starknet/CLAUDE.md (L54-54)
```markdown
- ✅ Transfer success validation for all external ERC20 calls
```
