### Title
Missing Recipient Validation in `initTransfer` Allows Permanent Loss of Bridged Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.initTransfer` and `initTransfer1155` accept a `string calldata recipient` with no validation that it is non-empty or represents a parseable cross-chain address. A user who calls either function with `recipient = ""` will have their tokens permanently burned or locked on the EVM side while the corresponding NEAR-side finalization is undeliverable, resulting in irreversible loss of bridged funds.

### Finding Description
`OmniBridge.initTransfer` burns or locks the caller's tokens before emitting an `InitTransfer` event that carries the raw `recipient` string to the NEAR side. [1](#0-0) 

No check is performed on `recipient` before the irreversible token operation executes: [2](#0-1) 

The same omission exists in `initTransfer1155`: [3](#0-2) 

On the NEAR side, `fin_transfer_callback` decodes the prover result and constructs a `TransferMessage` whose `recipient` field is typed as `OmniAddress`. An empty string cannot be parsed into any valid `OmniAddress` variant, so the NEAR-side call panics and the transfer is never finalized. [4](#0-3) 

The `OmniAddress` type has no empty-string variant; `is_zero()` for UTXO chains explicitly treats an empty string as the zero address, confirming the protocol recognizes this as an invalid state: [5](#0-4) 

The Solana SECURITY.md explicitly acknowledges the same class of bug for the Solana entry point but the EVM SECURITY.md does not list it as a known/accepted issue: [6](#0-5) 

### Impact Explanation
A user who calls `initTransfer(tokenAddress, amount, fee, nativeFee, "", "")` will have `amount` tokens burned (bridge tokens) or transferred into the contract (native ERC-20). The `InitTransfer` event is emitted with an empty recipient. The NEAR relayer submits the proof, but `fin_transfer_callback` panics when it cannot construct a valid `OmniAddress` from the empty string. No refund mechanism exists on the EVM side after the burn/lock has occurred. The funds are permanently frozen — matching the "permanent freezing of bridged funds" impact category.

### Likelihood Explanation
This is a user-mistake scenario identical in class to the referenced report. Any unprivileged EVM user can trigger it by accidentally omitting or zeroing the recipient field. No special role, signature, or collusion is required. The call is fully permissionless when the bridge is unpaused.

### Recommendation
Add an explicit non-empty check on `recipient` at the top of both `initTransfer` and `initTransfer1155`, before any token movement occurs:

```solidity
if (bytes(recipient).length == 0) revert InvalidRecipient();
```

Optionally enforce a minimum length consistent with the shortest valid cross-chain address format accepted by the NEAR prover.

### Proof of Concept
1. User holds 1000 USDC on EVM and approves `OmniBridge`.
2. User calls:
   ```solidity
   OmniBridge.initTransfer(
       usdcAddress,   // tokenAddress
       1000,          // amount
       0,             // fee
       0,             // nativeFee
       "",            // recipient  ← empty string, no revert
       ""             // message
   );
   ```
3. `IERC20(usdcAddress).safeTransferFrom(msg.sender, address(this), 1000)` executes — tokens are now held by the bridge.
4. `InitTransfer` event is emitted with `recipient = ""`.
5. NEAR relayer calls `fin_transfer` with the proof. `fin_transfer_callback` attempts to decode the recipient as `OmniAddress` and panics — the call fails.
6. No EVM-side refund path exists. The 1000 USDC are permanently locked in `OmniBridge`.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
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
    }
```

**File:** near/omni-types/src/lib.rs (L299-313)
```rust
    pub fn is_zero(&self) -> bool {
        match self {
            Self::Eth(address)
            | Self::Arb(address)
            | Self::Base(address)
            | Self::Bnb(address)
            | Self::Pol(address)
            | Self::HyperEvm(address)
            | Self::Abs(address) => address.is_zero(),
            Self::Near(address) => *address == ZERO_ACCOUNT_ID,
            Self::Sol(address) | Self::Fogo(address) => address.is_zero(),
            Self::Btc(address) | Self::Zcash(address) => address.is_empty(),
            Self::Strk(address) => address.is_zero(),
        }
    }
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
