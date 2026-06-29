### Title
Missing Zero-Address Recipient Validation in `init_transfer` Allows Permanent Loss of Bridged Funds - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

The `init_transfer` function in the NEAR omni-bridge contract does not validate that the recipient `OmniAddress` is not a zero address. A user can initiate a cross-chain transfer specifying `eth:0x0000000000000000000000000000000000000000` (or any chain's zero address) as the recipient. The MPC network will sign this payload, and when `finTransfer` is executed on the EVM side, bridged funds are either permanently burned (native ETH) or the transaction reverts leaving tokens permanently locked on NEAR with no recovery path.

---

### Finding Description

In `near/omni-bridge/src/lib.rs`, the `init_transfer` function validates only that the recipient chain is not NEAR:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
``` [1](#0-0) 

There is no check that `init_transfer_msg.recipient.is_zero()` is false. The `OmniAddress::is_zero()` method already exists in the shared type library:

```rust
pub fn is_zero(&self) -> bool {
    match self {
        Self::Eth(address) | Self::Arb(address) | ... => address.is_zero(),
        Self::Near(address) => *address == ZERO_ACCOUNT_ID,
        ...
    }
}
``` [2](#0-1) 

After `init_transfer` stores the transfer message and burns/locks the user's tokens, the relayer calls `sign_transfer`, which constructs a `TransferMessagePayload` with the zero recipient and requests an MPC signature: [3](#0-2) 

The MPC network signs whatever payload the bridge contract requests. The signed payload is then submitted to `finTransfer` on the EVM bridge:

```solidity
if (payload.tokenAddress == address(0)) {
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
``` [4](#0-3) 

When `payload.recipient == address(0)` and `tokenAddress == address(0)` (native ETH), the low-level `.call{value: amount}("")` to `address(0)` **succeeds** in the EVM — ETH is permanently burned. For ERC20 tokens, OpenZeppelin's `safeTransfer` to `address(0)` reverts, causing `finTransfer` to fail. In that case, the tokens remain permanently locked on NEAR because there is no cancellation or refund mechanism for a stored transfer message. [5](#0-4) 

---

### Impact Explanation

- **Native ETH path**: User bridges wETH (NEP-141) on NEAR specifying `eth:0x0000000000000000000000000000000000000000` as recipient. Tokens are burned on NEAR. `finTransfer` on EVM sends ETH to `address(0)` — call succeeds, ETH is permanently destroyed.
- **ERC20/bridge-token path**: `finTransfer` reverts (OpenZeppelin zero-address guard). The nonce is already marked used (`completedTransfers[nonce] = true`), so the transfer cannot be retried. Tokens remain locked on NEAR with no recovery path — permanent freeze of bridged funds.

Both outcomes constitute **permanent loss or freezing of bridged funds**, matching the Critical impact scope.

---

### Likelihood Explanation

The entry point is `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, callable by any unprivileged token holder. A user can accidentally or intentionally supply a zero EVM address as the recipient string (e.g., `"eth:0x0000000000000000000000000000000000000000"`). No privileged access is required. The `OmniAddress` type accepts and parses this value without error, and the bridge contract stores and processes it without rejection. [6](#0-5) 

---

### Recommendation

Add a zero-address guard in `init_transfer` immediately after the chain-kind check, using the already-available `OmniAddress::is_zero()` method:

```rust
require!(
    init_transfer_msg.recipient.get_chain() != ChainKind::Near,
    BridgeError::InvalidRecipientChain.as_ref()
);
require!(
    !init_transfer_msg.recipient.is_zero(),
    BridgeError::InvalidRecipientAddress.as_ref()
);
```

Apply the same guard in `finish_withdraw_v2` and any other entry point that accepts a user-supplied recipient address. [7](#0-6) 

---

### Proof of Concept

1. User holds 1 wETH (NEP-141) on NEAR.
2. User calls `ft_transfer_call` on the wETH token contract with:
   - `receiver_id`: omni-bridge contract
   - `msg`: `InitTransfer` with `recipient = "eth:0x0000000000000000000000000000000000000000"`, `fee = 0`
3. `init_transfer` passes the chain-kind check (`Eth != Near`), stores the transfer, burns 1 wETH on NEAR.
4. Relayer calls `sign_transfer`; MPC signs the payload containing `recipient = address(0)`.
5. Relayer calls `finTransfer` on the EVM bridge with the valid MPC signature and `payload.recipient = address(0)`, `payload.tokenAddress = address(0)` (native ETH).
6. EVM executes `address(0).call{value: 1 ether}("")` → returns `success = true`.
7. 1 ETH is permanently burned. User's wETH on NEAR is already gone. Funds are irrecoverably lost. [8](#0-7)

### Citations

**File:** near/omni-bridge/src/lib.rs (L491-500)
```rust
        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1314-1354)
```rust
    #[allow(clippy::needless_pass_by_value)]
    pub fn finish_withdraw_v2(
        &mut self,
        #[serializer(borsh)] sender_id: &AccountId,
        #[serializer(borsh)] amount: u128,
        #[serializer(borsh)] recipient: String,
    ) {
        let token_id = env::predecessor_account_id();
        require!(self.is_deployed_token(&token_id),);

        self.current_origin_nonce += 1;
        let destination_nonce = self.get_next_destination_nonce(ChainKind::Eth);

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount: U128(amount),
            recipient: OmniAddress::Eth(
                H160::from_str(&recipient).near_expect(BridgeError::InvalidRecipientAddress),
            ),
            fee: Fee {
                fee: U128(0),
                native_fee: U128(0),
            },
            sender: OmniAddress::Near(sender_id.clone()),
            msg: String::new(),
            destination_nonce,
            origin_transfer_id: None,
        };

        let required_storage_balance =
            self.add_transfer_message(transfer_message.clone(), sender_id.clone());

        self.update_storage_balance(
            env::current_account_id(),
            required_storage_balance,
            NearToken::from_yoctonear(0),
        );

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
    }
```

**File:** near/omni-types/src/lib.rs (L197-213)
```rust
    pub fn new_zero(chain_kind: ChainKind) -> Result<Self, String> {
        match chain_kind {
            ChainKind::Eth => Ok(Self::Eth(H160::ZERO)),
            ChainKind::Near => Ok(Self::Near(ZERO_ACCOUNT_ID.parse().map_err(stringify)?)),
            ChainKind::Sol => Ok(Self::Sol(SolAddress::ZERO)),
            ChainKind::Arb => Ok(Self::Arb(H160::ZERO)),
            ChainKind::Base => Ok(Self::Base(H160::ZERO)),
            ChainKind::Bnb => Ok(Self::Bnb(H160::ZERO)),
            ChainKind::Pol => Ok(Self::Pol(H160::ZERO)),
            ChainKind::HyperEvm => Ok(Self::HyperEvm(H160::ZERO)),
            ChainKind::Btc => Ok(Self::Btc(String::new())),
            ChainKind::Zcash => Ok(Self::Zcash(String::new())),
            ChainKind::Strk => Ok(Self::Strk(H256::ZERO)),
            ChainKind::Abs => Ok(Self::Abs(H160::ZERO)),
            ChainKind::Fogo => Ok(Self::Fogo(SolAddress::ZERO)),
        }
    }
```

**File:** near/omni-types/src/lib.rs (L299-312)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
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
    }
```
