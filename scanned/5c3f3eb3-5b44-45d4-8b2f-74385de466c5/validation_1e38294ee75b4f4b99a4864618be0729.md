### Title
Fee-on-Transfer Token Balance Mis-Accounting in `initTransfer` Emits Inflated Amount, Enabling NEAR-Side Over-Minting - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer()` on the EVM side performs a `safeTransferFrom` for the caller-supplied `amount`, then unconditionally emits `InitTransfer` with that same `amount` — without checking the actual balance received. For fee-on-transfer ERC20 tokens, the bridge receives fewer tokens than `amount`, but the NEAR prover reads the emitted `amount` from the event log and mints/unlocks the full `amount` on NEAR. This permanently inflates the NEAR-side supply relative to the EVM-side escrow, making the EVM bridge insolvent for that token.

---

### Finding Description

In `OmniBridge.initTransfer()`, when `tokenAddress` is neither a bridge token nor a custom-minter token, the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // requested amount, not verified received amount
);
```

Immediately after, it emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-supplied amount, not actual balance delta
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) [2](#0-1) 

No before/after balance check is performed. For a fee-on-transfer token (e.g., USDT in fee mode, STA), `safeTransferFrom` delivers `amount - transfer_fee` to `address(this)`, but the event records `amount`.

The NEAR bridge's `fin_transfer_callback` decodes the `InitTransfer` event log via the prover and constructs a `TransferMessage` using the `amount` field from the event:

```rust
let transfer_message = TransferMessage {
    ...
    amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
    ...
};
``` [3](#0-2) 

This `amount` is then used to mint or unlock tokens on NEAR for the recipient, with no cross-check against what the EVM bridge actually holds.

The same pattern exists in the Starknet bridge's `init_transfer`:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
// ...
emit InitTransfer { ..., amount, ... }  // emits caller-supplied amount
``` [4](#0-3) 

---

### Impact Explanation

Each `initTransfer` call with a fee-on-transfer token creates a deficit: the EVM bridge holds `amount - fee_on_transfer` tokens, but NEAR mints `amount` tokens. Over multiple transfers, the EVM escrow becomes insolvent. When NEAR-side holders attempt to bridge back (triggering `finTransfer` on EVM), the bridge cannot fulfill withdrawals for the full amount, causing permanent loss of funds for later users. The protocol's `locked_tokens` accounting on NEAR also diverges from the actual EVM balance, corrupting the cross-chain invariant.

---

### Likelihood Explanation

The `logMetadata` function is permissionless — any user can register any ERC20 token address with the bridge:

```solidity
function logMetadata(address tokenAddress) external payable {
``` [5](#0-4) 

After the NEAR side processes the `LogMetadata` event via `bind_token` (which only checks that the emitter is the registered factory — satisfied since `logMetadata` is called on the official bridge contract), the token is live. A user then calls `initTransfer` with a fee-on-transfer token. No admin action or privilege is required beyond the initial `logMetadata` call. Fee-on-transfer tokens are real and deployed on mainnet (USDT has a configurable fee mode; STA is a known example).

---

### Recommendation

Record the actual balance received by performing a before/after balance check:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(actualReceived == amount, "FEE_ON_TRANSFER_NOT_SUPPORTED");
// or: use actualReceived in the emitted event
```

Either enforce that `actualReceived == amount` (disallowing fee-on-transfer tokens), or emit `actualReceived` in the `InitTransfer` event so the NEAR side mints only what was truly locked. Apply the same fix to the Starknet `init_transfer`.

---

### Proof of Concept

1. Deploy or identify a fee-on-transfer ERC20 token `T` with a 1% transfer fee on mainnet.
2. Call `OmniBridge.logMetadata(T)` — permissionless, emits `LogMetadata`.
3. NEAR relayer submits proof; NEAR `bind_token` registers `T` (emitter is the registered factory).
4. Call `OmniBridge.initTransfer(T, 1_000_000, 0, 0, "alice.near", "")`.
   - `safeTransferFrom` delivers `990_000` tokens to the bridge (1% fee deducted).
   - `emit InitTransfer(..., 1_000_000, ...)` records the full `1_000_000`.
5. NEAR relayer submits proof of the `InitTransfer` event.
6. NEAR `fin_transfer_callback` reads `amount = 1_000_000` and mints `1_000_000` wrapped-T to `alice.near`.
7. EVM bridge holds only `990_000` T. Deficit of `10_000` T per transfer.
8. After sufficient transfers, EVM bridge cannot honor withdrawals — funds are permanently lost for later redeemers. [6](#0-5) [7](#0-6)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L406-436)
```text
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

**File:** near/omni-bridge/src/lib.rs (L698-745)
```rust
    #[private]
    #[payable]
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
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

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
```

**File:** starknet/src/omni_bridge.cairo (L304-330)
```text
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
```
