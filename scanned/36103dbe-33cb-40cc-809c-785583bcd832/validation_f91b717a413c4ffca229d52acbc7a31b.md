### Title
Missing Self-Address Validation in `finTransfer` Allows Permanent Freezing of Bridged Tokens — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.sol::finTransfer` does not validate that `payload.recipient != address(this)`. A user on NEAR can initiate a transfer specifying the EVM OmniBridge contract address as the recipient. The NEAR MPC signs the payload without restriction, and when a relayer calls `finTransfer`, tokens are minted or transferred directly into the OmniBridge contract, where they become permanently irrecoverable.

### Finding Description
In `finTransfer`, after verifying the MPC signature, the contract dispatches tokens to `payload.recipient` via one of four paths — none of which check whether `payload.recipient == address(this)`: [1](#0-0) 

The `payload.recipient` field is ultimately controlled by the user who initiates the transfer on NEAR via `ft_on_transfer` → `init_transfer`. The NEAR-side `init_transfer` only validates that the recipient chain is not NEAR: [2](#0-1) 

It does not prevent the user from specifying the EVM OmniBridge contract address as the EVM recipient. The NEAR MPC then signs the payload containing that address, and a relayer submits it to `finTransfer`.

When `payload.recipient == address(this)`:

- **Bridge tokens**: `IBridgeToken(payload.tokenAddress).mint(address(OmniBridge), amount)` is called. The OmniBridge is the owner of `BridgeToken` and can call `burn(account, value)` on it, but the OmniBridge contract has no internal function to burn tokens it holds. `initTransfer` only burns from `msg.sender`, not from the contract's own balance. The minted tokens are permanently stuck. [3](#0-2) 

- **Native ERC20 tokens**: `IERC20(payload.tokenAddress).safeTransfer(address(OmniBridge), amount)` is called. The OmniBridge has no sweep or recovery function. The tokens are permanently stuck. [4](#0-3) 

The same structural gap exists on the NEAR side: `process_fin_transfer_to_near` calls `send_tokens` with the attacker-supplied `recipient` without checking `recipient != env::current_account_id()`, so the symmetric attack (EVM user specifying the NEAR bridge contract address) also permanently freezes tokens in the NEAR bridge contract. [5](#0-4) 

### Impact Explanation
Bridged funds are permanently frozen with no recovery path. For bridge tokens, the total supply increases (tokens are minted) but the OmniBridge holds them and cannot burn or transfer them out. For native tokens, the locked collateral pool is inflated by the stuck tokens with no sweep mechanism. This is a direct instance of "permanent freezing of bridged funds" in the allowed impact scope.

### Likelihood Explanation
Any unprivileged NEAR user can trigger this by calling `ft_on_transfer` with `recipient = OmniAddress::Eth(<omni_bridge_address>)`. The NEAR bridge accepts any EVM address as recipient (only rejecting NEAR-chain recipients). The NEAR MPC signs the payload without inspecting the recipient address. A standard relayer then submits `finTransfer`. The attack requires no special role, no admin compromise, and no colluding MPC nodes. It can occur accidentally (user pastes the wrong address) or deliberately.

### Recommendation
Add a recipient self-address guard in `finTransfer`:

```solidity
if (

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
```text
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
```

**File:** near/omni-bridge/src/lib.rs (L531-534)
```rust
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );
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
