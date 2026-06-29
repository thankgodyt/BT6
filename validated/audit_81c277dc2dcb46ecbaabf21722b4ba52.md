Let me examine the relevant Solana bridge code to trace this exploit path.

Let me check the `FinalizeTransferPayload` structure and how the NEAR side generates it, plus whether the Solana side validates the mint against the payload's token field.

Let me check how `verify_signature` is called in the `finalize_transfer` instruction handler.