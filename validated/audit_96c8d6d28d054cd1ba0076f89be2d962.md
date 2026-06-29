After thorough analysis of the NEAR Omni Bridge codebase, I examined every plausible analog to the reported vulnerability class — a guard condition that incorrectly blocks fund withdrawal when a balance reaches zero through a legitimate path (full repayment/liquidation), causing funds to be permanently locked.

**Patterns examined:**

1. **`unlock_tokens_if_needed` zero-amount guard** (`near/omni-bridge/src/token_lock.rs:115`): Returns `LockAction::Unchanged` when `amount == 0`. This is correct behavior — there is nothing to unlock when the fee or amount is zero.

2. **`send_fee_internal` zero-fee guard** (`near/omni-bridge/src/lib.rs:2686`): Skips token transfer when `token_fee == 0`. This is correct — when fee is zero, no tokens need to be sent to the fee recipient, and the `locked_tokens` counter correctly reflects tokens remaining on the destination chain.

3. **`sign_transfer` zero-amount guard** (`near/omni-bridge/src/lib.rs:482–485`):