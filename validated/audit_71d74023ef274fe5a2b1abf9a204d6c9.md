### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` Emits Inflated Amount, Enabling Over-Minting on NEAR - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `initTransfer` function performs a `safeTransferFrom` of a caller-supplied `amount` for plain ERC-20 tokens, then unconditionally emits `InitTransfer` with that same `amount`. For Fee-on-Transfer (FoT) tokens the contract actually receives `amount - transfer_fee`, but the event records the full `amount`. The NEAR bridge reads the event amount directly from the prover result and mints or unlocks that full `amount` on NEAR, creating a permanent deficit in the EVM escrow.

---

### Finding Description

In `OmniBridge.sol`, the `initTransfer` function handles plain ERC-20 tokens (those that are neither bridge tokens nor custom-minter tokens) with:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied, not verified against actual receipt
);
```

Immediately after, the event is emitted with the same caller-supplied `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // inflated for FoT tokens
    fee,
    nativeFee,
    recipient,
    message
);
```

No balance-before / balance-after check is performed to determine the actual received amount.

On the NEAR side, `fin_transfer_callback` decodes the prover result and constructs the `TransferMessage` directly from `init_transfer.amount`:

```rust
let transfer_message = TransferMessage {
    ...
    amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
    ...
};
```

`process_fin_transfer_to_near` then calls `send_tokens` with `transfer_message.amount_without_fee()`, which is derived from the event-recorded `amount`, not the actual EVM-locked amount. For a deployed (bridged) token the bridge mints; for a native token it transfers from its own balance — in both cases the NEAR side disburses more than was actually locked on EVM.

The identical pattern exists in `starknet/src/omni_bridge.cairo`'s `init_transfer`:

```cairo
let success = IERC20Dispatcher { contract_address: token_address }
    .transfer_from(caller, get_contract_address(), amount.into());
// event emits `amount` — no actual-receipt check
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Each `initTransfer` call with a FoT token causes the EVM bridge to hold `amount - transfer_fee` tokens while NEAR records and eventually disburses `amount` tokens. The deficit accumulates with every such transfer. When users attempt to bridge back from NEAR to EVM, the EVM bridge will have insufficient tokens to honor all redemptions. The last user(s) to redeem will find the bridge insolvent and their funds permanently frozen. An attacker can deliberately exploit this to drain the EVM escrow by repeatedly bridging FoT tokens, leaving legitimate users unable to withdraw.

This is a **Critical** escrow mis-accounting / permanent freezing of bridged funds. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

Any unprivileged user can call `initTransfer` with any ERC-20 token address that is not registered as a bridge token or custom-minter token. FoT tokens (e.g., USDT on some chains, deflationary tokens) are widely deployed. No special role or permission is required. The attacker-controlled entry path is the public `initTransfer` function. [7](#0-6) 

---

### Recommendation

Measure the actual received amount using a balance-before / balance-after check and use that value in the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 balanceAfter = IERC20(tokenAddress).balanceOf(address(this));
uint128 actualReceived = uint128(balanceAfter - balanceBefore);
// use actualReceived in the event and all downstream accounting
```

Apply the same fix to `starknet/src/omni_bridge.cairo`'s `init_transfer`. Alternatively, document explicitly that FoT and rebasing tokens are not supported and add an allowlist/denylist enforced on-chain. [8](#0-7) [9](#0-8) 

---

### Proof of Concept

1. Deploy or use an existing FoT ERC-20 token on an EVM chain supported by the bridge (e.g., Ethereum). The token charges a 1% fee on every transfer.
2. Call `OmniBridge.initTransfer(fotToken, 1_000_000, 0, 0, "near:victim.near", "")`.
3. The bridge receives `990_000` tokens (`1_000_000 - 1%`), but emits `InitTransfer(..., amount=1_000_000, ...)`.
4. A relayer submits the EVM receipt proof to the NEAR bridge via `fin_transfer`.
5. `fin_transfer_callback` decodes `init_transfer.amount = 1_000_000` and mints/transfers `1_000_000` tokens to `victim.near`.
6. Repeat N times. The EVM bridge now holds `N × 990_000` tokens but NEAR has minted `N × 1_000_000`.
7. When any user tries to bridge back from NEAR to EVM, the EVM bridge cannot cover the full redemption for the last `N × 10_000` tokens — those funds are permanently frozen. [10](#0-9) [11](#0-10)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
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

**File:** near/omni-bridge/src/lib.rs (L1957-1966)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
        )
```

**File:** starknet/src/omni_bridge.cairo (L303-307)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```

**File:** near/omni-bridge/src/token_lock.rs (L71-94)
```rust
    fn unlock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(available) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        require!(
            available >= amount,
            TokenLockError::InsufficientLockedTokens.as_ref()
        );

        let remaining = available - amount;
        self.locked_tokens.insert(&key, &remaining);

        LockAction::Unlocked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
    }
```

**File:** near/omni-types/src/prover_result.rs (L9-18)
```rust
pub struct InitTransferMessage {
    pub origin_nonce: Nonce,
    pub token: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub sender: OmniAddress,
    pub msg: String,
    pub emitter_address: OmniAddress,
}
```
