### Title
Deflationary/Fee-on-Transfer ERC20 Token Escrow Mis-Accounting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` records and emits the caller-supplied `amount` rather than the actual tokens received. For deflationary or fee-on-transfer ERC20 tokens the two values diverge, causing the EVM escrow to be permanently undercollateralized while the NEAR side mints the full requested amount — enabling theft of other users' locked funds.

---

### Finding Description

In `OmniBridge.initTransfer`, the non-bridge, non-custom-minter ERC20 path (the `else` branch) pulls tokens from the caller and immediately emits the event using the caller-controlled `amount` parameter:

```solidity
// evm/src/omni-bridge/contracts/OmniBridge.sol  lines 406-436
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount          // ← requested amount, not actual received
    );
}
// ...
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,             // ← same requested amount goes into the event
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) 

For a deflationary token (e.g., one that deducts a 1 % transfer tax), `safeTransferFrom` succeeds but the contract receives only `amount × 0.99`. No balance-before/balance-after check exists anywhere in the function.

The `InitTransfer` event is the **sole** data source the NEAR side consumes. The project's own security documentation states:

> "The NEAR side reads this event (via light client or Wormhole) to complete the transfer. Every field needed to reconstruct the transfer must be in the event — it is the only data the NEAR side sees." [2](#0-1) 

`fin_transfer_callback` on NEAR reads `init_transfer.amount` directly from the prover result (which is derived from the event) and uses it verbatim to mint or release tokens to the recipient:

```rust
// near/omni-bridge/src/lib.rs  line 725
amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
``` [3](#0-2) 

The identical pattern exists in the Starknet contract:

```cairo
// starknet/src/omni_bridge.cairo  lines 303-306
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
// ...emits amount unchanged
``` [4](#0-3) 

There is no token allowlist or registration gate in `initTransfer`; any ERC20 address is accepted. [5](#0-4) 

---

### Impact Explanation

Each `initTransfer` call with a deflationary token creates a deficit: the EVM bridge holds `amount - tax` tokens but the NEAR side mints `amount` tokens. The deficit accumulates with every such transfer. When legitimate users who previously locked non-deflationary tokens of the same type attempt to bridge back (NEAR → EVM via `finTransfer`), the EVM bridge's `safeTransfer` will fail or drain reserves belonging to other depositors, permanently freezing their funds. The attacker personally profits by receiving more tokens on the destination chain than were actually escrowed. [6](#0-5) 

---

### Likelihood Explanation

`initTransfer` is a public, permissionless function callable by any address with no token allowlist. Deflationary and fee-on-transfer ERC20 tokens are widely deployed on Ethereum mainnet and all supported EVM chains. No special role, leaked key, or off-chain coordination is required; a single transaction is sufficient to trigger the mis-accounting. [7](#0-6) 

---

### Recommendation

Measure the actual received amount using a balance-before / balance-after pattern and use that value in the event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(actualReceived == amount, "DeflatoryTokenNotSupported");
// or: use actualReceived as the bridged amount
```

Alternatively, explicitly restrict `initTransfer` to tokens registered via `deployToken` / `addCustomToken`, which are bridge-controlled and cannot be deflationary.

Apply the same fix to the Starknet `init_transfer`. [8](#0-7) 

---

### Proof of Concept

1. Deploy or use any existing fee-on-transfer ERC20 token `T` (e.g., 1 % transfer tax) on an EVM chain supported by the bridge.
2. Approve the OmniBridge contract for `1 000 T`.
3. Call `OmniBridge.initTransfer(T, 1000, 0, 0, "near:attacker.near", "")`.
   - `safeTransferFrom` executes; bridge receives `990 T`.
   - Event emits `amount = 1000`.
4. A relayer submits the event proof to the NEAR bridge via `fin_transfer`.
5. NEAR `fin_transfer_callback` reads `amount = 1000` from the `InitTransferMessage` and mints `1000 T` (wrapped) to `attacker.near`.
6. Attacker now holds `1000` wrapped tokens while the EVM bridge only holds `990 T`.
7. Attacker bridges `1000` wrapped tokens back (NEAR → EVM). The NEAR bridge burns `1000` and signs a release of `1000 T` on EVM.
8. `finTransfer` on EVM attempts `safeTransfer(attacker, 1000 T)` — the bridge only has `990 T` from this deposit. The shortfall (`10 T`) is taken from other users' locked reserves, permanently freezing an equivalent amount of legitimate deposits. [9](#0-8) [10](#0-9)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-366)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
```

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
