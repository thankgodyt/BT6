### Title
Native Fee (STRK) Collected in `init_transfer` Is Never Paid Out in `fin_transfer`, Causing Permanent Fund Loss — (`starknet/src/omni_bridge.cairo`)

### Summary

The Starknet `OmniBridge` contract collects a `native_fee` denominated in a hardcoded single token (`strk_token_address`) during `init_transfer`. However, `fin_transfer` — the function that finalizes inbound transfers and pays the fee recipient — never releases these collected STRK tokens. The STRK native fees are permanently locked in the Starknet bridge contract, while the NEAR side independently mints bridged STRK to the fee recipient, creating an unbacked token supply inflation.

### Finding Description

In `starknet/src/omni_bridge.cairo`, the `init_transfer` function accepts a `native_fee` parameter. When `native_fee > 0`, it reads a single hardcoded storage slot `strk_token_address` and pulls that amount of STRK from the caller into the bridge contract:

```cairo
if native_fee > 0 {
    let native_token = self.strk_token_address.read();
    let success = IERC20Dispatcher { contract_address: native_token }
        .transfer_from(caller, get_contract_address(), native_fee.into());
    assert(success, 'ERR_FEE_TRANSFER_FAILED');
}
``` [1](#0-0) 

The `InitTransfer` event emits the `native_fee` amount but **not** the token address used: [2](#0-1) 

The `fin_transfer` function — which finalizes NEAR→Starknet transfers and is the only other state-changing function — mints or transfers the bridged token to the recipient and emits a `FinTransfer` event, but **never pays out any STRK native fee to the `fee_recipient`**: [3](#0-2) 

Meanwhile, on the NEAR side, when finalizing a Starknet→NEAR transfer, the bridge independently mints bridged STRK tokens to the fee recipient based on the `native_fee` field parsed from the Starknet event:

```rust
if transfer_message.fee.native_fee.0 > 0 {
    let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());
    ext_token::ext(native_token_id)
        .with_static_gas(MINT_TOKEN_GAS)
        .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
        .detach();
}
``` [4](#0-3) 

`get_native_token_id(ChainKind::Strk)` resolves to the hardcoded STRK address `strk:0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`: [5](#0-4) 

The result is a two-sided accounting failure:
1. Real STRK tokens are locked forever in the Starknet bridge (no release path exists).
2. NEAR mints new bridged STRK to the fee recipient without any corresponding unlock on Starknet, inflating the bridged STRK supply.

### Impact Explanation

Every `init_transfer` call on Starknet with `native_fee > 0` permanently locks STRK tokens in the bridge contract. There is no function in the Starknet contract that releases these tokens to the fee recipient. Simultaneously, NEAR mints unbacked bridged STRK, breaking the 1:1 escrow invariant. This constitutes:
- **Permanent freezing of user-paid STRK native fees** in the Starknet bridge.
- **Unauthorized minting / escrow mis-accounting**: bridged STRK supply on NEAR grows without corresponding STRK backing on Starknet.

### Likelihood Explanation

Any user who calls `init_transfer` on Starknet with a non-zero `native_fee` triggers this bug. This is a standard user-facing function with no access control. Relayers routinely request non-zero native fees to cover their costs. The path is fully reachable by any unprivileged bridge user.

### Recommendation

The `fin_transfer` function on Starknet must pay out the `native_fee` (in STRK) to the `fee_recipient` specified in the payload, mirroring how the NEAR side handles it. Alternatively, the Starknet `init_transfer` event should include the native fee token address so the NEAR side can correctly account for it, and a dedicated fee-claim mechanism should be added to the Starknet contract.

### Proof of Concept

1. User on Starknet approves the bridge to spend 100 STRK and calls:
   ```
   init_transfer(token_address=<some_erc20>, amount=1000, fee=10, native_fee=100, recipient="alice.near", message="")
   ```
2. Bridge pulls 100 STRK from user into itself via `strk_token_address`. Event emitted with `native_fee=100`.
3. NEAR relayer parses the event, stores `fee.native_fee = 100`.
4. Relayer calls `sign_transfer` on NEAR; MPC signs; relayer submits to Starknet's `fin_transfer` (for the reverse direction) — but this is irrelevant; the Starknet→NEAR path finalizes on NEAR.
5. NEAR's `fin_transfer_send_tokens_callback` mints 100 bridged-STRK to the fee recipient on NEAR.
6. The 100 real STRK remain locked in the Starknet bridge forever — no function exists to release them.

### Citations

**File:** starknet/src/omni_bridge.cairo (L242-279)
```text
        fn fin_transfer(
            ref self: ContractState, signature: Signature, payload: TransferMessagePayload,
        ) {
            assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');

            assert(
                !self.is_transfer_finalised(payload.destination_nonce), 'ERR_NONCE_ALREADY_USED',
            );
            _set_transfer_finalised(ref self, payload.destination_nonce);

            _verify_borsh_signature(
                ref self, @payload.to_borsh(self.omni_bridge_chain_id.read()), signature,
            );

            if self.is_bridge_token(payload.token_address) {
                IBridgeTokenDispatcher { contract_address: payload.token_address }
                    .mint(payload.recipient, payload.amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: payload.token_address }
                    .transfer(payload.recipient, payload.amount.into());
                assert(success, 'ERR_TRANSFER_FAILED');
            }

            self
                .emit(
                    Event::FinTransfer(
                        FinTransfer {
                            origin_chain: payload.origin_chain,
                            origin_nonce: payload.origin_nonce,
                            token_address: payload.token_address,
                            amount: payload.amount,
                            recipient: payload.recipient,
                            fee_recipient: payload.fee_recipient,
                            message: payload.message,
                        },
                    ),
                )
        }
```

**File:** starknet/src/omni_bridge.cairo (L309-314)
```text
            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L316-331)
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
        }
```

**File:** near/omni-bridge/src/lib.rs (L1736-1743)
```rust
            if transfer_message.fee.native_fee.0 > 0 {
                let native_token_id = self.get_native_token_id(transfer_message.get_origin_chain());

                ext_token::ext(native_token_id)
                    .with_static_gas(MINT_TOKEN_GAS)
                    .mint(fee_recipient.clone(), transfer_message.fee.native_fee, None)
                    .detach();
            }
```

**File:** near/omni-types/src/lib.rs (L944-961)
```rust
pub fn get_native_token_address(chain_kind: ChainKind) -> Result<OmniAddress, String> {
    match chain_kind {
        ChainKind::Strk => OmniAddress::from_str(
            "strk:0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
        ),
        ChainKind::Eth
        | ChainKind::Near
        | ChainKind::Sol
        | ChainKind::Arb
        | ChainKind::Base
        | ChainKind::Bnb
        | ChainKind::Btc
        | ChainKind::Zcash
        | ChainKind::Pol
        | ChainKind::HyperEvm
        | ChainKind::Abs
        | ChainKind::Fogo => OmniAddress::new_zero(chain_kind),
    }
```
