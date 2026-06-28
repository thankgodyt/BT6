### Title
Rebasing Token Balance Mis-Accounting in `initTransfer` Enables Cross-Chain Fund Theft — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The EVM `OmniBridge.initTransfer` function emits the user-supplied `amount` parameter directly in the `InitTransfer` event without measuring the actual tokens received by the contract. For rebasing tokens (e.g., AMPL), the contract's real token balance can shrink after deposit due to a negative rebase, while NEAR has already minted the full `amount` of bridge tokens based on the event. An attacker who deposits before a negative rebase and bridges back after it receives their full nominal amount, draining tokens that belong to other depositors.

---

### Finding Description

In `OmniBridge.initTransfer`, the native-token lock path (the `else` branch) performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // ← transfers `amount` at current rebase rate
);
```

and then immediately emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // ← user-supplied parameter, NOT actual received
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) 

There is no balance-before/balance-after measurement. The emitted `amount` is taken verbatim from the call parameter.

On the NEAR side, `fin_transfer_callback` reads this event via a prover and uses `init_transfer.amount` to mint or unlock tokens: [2](#0-1) 

The NEAR contract's `locked_tokens` map is incremented by the event's `amount` value, not by any on-chain balance measurement: [3](#0-2) 

When a user later bridges back (NEAR → EVM), the MPC signs a payload containing the same `amount`, and `finTransfer` on EVM calls:

```solidity
IERC20(payload.tokenAddress).safeTransfer(payload.recipient, payload.amount);
``` [4](#0-3) 

If a negative rebase has occurred between deposit and withdrawal, the EVM contract holds fewer tokens than the sum of all recorded event amounts. The first user to bridge back receives their full nominal amount, draining tokens that belong to later depositors.

The same root cause exists in the Starknet contract, which also emits `amount` directly without measuring actual received: [5](#0-4) 

---

### Impact Explanation

**Concrete theft scenario (negative rebase):**

1. Attacker deposits 1,000 AMPL on EVM when `_gonsPerFragment = 1`. EVM contract holds 1,000 AMPL. `InitTransfer` event emits `amount = 1000`. NEAR mints 1,000 omni-AMPL to attacker.
2. A negative rebase fires: `_gonsPerFragment = 2`. Every holder's balance halves. EVM contract now holds **500 AMPL** in real terms, but NEAR still has 1,000 omni-AMPL minted.
3. Victim deposits 1,000 AMPL (at the new rate). Event emits `amount = 1000`. NEAR mints 1,000 omni-AMPL to victim. EVM contract now holds **1,500 AMPL**.
4. Attacker bridges back 1,000 omni-AMPL. NEAR burns 1,000 omni-AMPL, MPC signs for EVM to release 1,000 AMPL. `finTransfer` succeeds (1,500 ≥ 1,000). EVM now holds **500 AMPL**.
5. Victim bridges back 1,000 omni-AMPL. NEAR burns 1,000 omni-AMPL, MPC signs for EVM to release 1,000 AMPL. `finTransfer` **reverts** — only 500 AMPL remain.
6. Victim permanently loses 500 AMPL. Attacker received 1,000 AMPL despite their deposit being worth only 500 AMPL post-rebase.

The attacker's profit comes entirely from the victim's deposit. This is a direct, irreversible theft of bridged funds.

A positive rebase causes the inverse: tokens accumulate in the EVM contract with no corresponding NEAR accounting, permanently locking the surplus.

---

### Likelihood Explanation

The bridge is designed to support arbitrary ERC20 tokens via the native lock path (the `else` branch in `initTransfer`). Any rebasing token that is not registered as a `isBridgeToken` or `customMinters` entry will follow this path. Rebasing tokens (AMPL, stETH rebase variants, etc.) are a well-known token class. The attacker does not need any special role — they only need to call the public `initTransfer` function and time their withdrawal around a rebase event, which is publicly observable on-chain and can be front-run.

---

### Recommendation

Measure the actual tokens received by comparing balances before and after the transfer, and use the measured amount in the emitted event:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint128 actualReceived = uint128(IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore);
// Use actualReceived instead of amount in the event and extension call
```

This fixes the fee-on-transfer discrepancy at deposit time. For rebasing tokens specifically, the deeper issue is that the EVM contract holds a nominal balance that can drift from NEAR's `locked_tokens` accounting at any time. A more robust solution is to track depositor **shares** (gons for AMPL) rather than nominal amounts, or to explicitly exclude rebasing tokens from the native lock path.

Apply the same fix to the Starknet `init_transfer` function.

---

### Proof of Concept

```
State:
  EVM OmniBridge holds AMPL (rebasing token, _gonsPerFragment = 1)
  NEAR omni-bridge has locked_tokens[Eth][AMPL] = 0

Step 1 — Attacker deposits:
  attacker calls OmniBridge.initTransfer(AMPL, 1000, 0, 0, "attacker.near", "")
  → safeTransferFrom(attacker, bridge, 1000) succeeds
  → emit InitTransfer(..., amount=1000, ...)
  → Relayer submits proof to NEAR fin_transfer
  → NEAR mints 1000 omni-AMPL to attacker.near
  → locked_tokens[Eth][AMPL] = 1000

Step 2 — Negative rebase:
  AMPL.rebase() sets _gonsPerFragment = 2
  → bridge's AMPL balance: 1000 / 2 = 500 (real tokens)
  → NEAR locked_tokens[Eth][AMPL] still = 1000  ← DIVERGENCE

Step 3 — Victim deposits:
  victim calls OmniBridge.initTransfer(AMPL, 1000, 0, 0, "victim.near", "")
  → safeTransferFrom(victim, bridge, 1000) succeeds (at new rate)
  → emit InitTransfer(..., amount=1000, ...)
  → NEAR mints 1000 omni-AMPL to victim.near
  → locked_tokens[Eth][AMPL] = 2000
  → bridge's AMPL balance: 500 + 1000 = 1500

Step 4 — Attacker bridges back:
  attacker calls NEAR ft_transfer_call → init_transfer → MPC signs payload(amount=1000)
  → OmniBridge.finTransfer(sig, {tokenAddress=AMPL, amount=1000, recipient=attacker})
  → safeTransfer(attacker, 1000) succeeds (1500 >= 1000)
  → bridge's AMPL balance: 500

Step 5 — Victim bridges back:
  victim calls NEAR ft_transfer_call → init_transfer → MPC signs payload(amount=1000)
  → OmniBridge.finTransfer(sig, {tokenAddress=AMPL, amount=1000, recipient=victim})
  → safeTransfer(victim, 1000) REVERTS — only 500 AMPL remain
  → Victim's 1000 omni-AMPL are burned on NEAR but EVM transfer fails
  → Victim loses 500 AMPL permanently
```

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L350-355)
```text
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
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

**File:** near/omni-bridge/src/token_lock.rs (L48-68)
```rust
    fn lock_tokens(
        &mut self,
        chain_kind: ChainKind,
        token_id: &AccountId,
        amount: u128,
    ) -> LockAction {
        let key = (chain_kind, token_id.clone());
        let Some(current_amount) = self.locked_tokens.get(&key) else {
            return LockAction::Unchanged;
        };
        let new_amount = current_amount
            .checked_add(amount)
            .near_expect(TokenLockError::LockedTokensOverflow);

        self.locked_tokens.insert(&key, &new_amount);

        LockAction::Locked {
            chain_kind,
            token_id: token_id.clone(),
            amount,
        }
```

**File:** starknet/src/omni_bridge.cairo (L303-330)
```text
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
```
