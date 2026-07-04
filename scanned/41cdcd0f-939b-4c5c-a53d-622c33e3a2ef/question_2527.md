# Q2527: future headers queued until slot becomes current in HeaderArrivalException

## Question
Can an unprivileged attacker reach HeaderArrivalException with future headers queued until slot becomes current and normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing, then make an invalid block or ledger state appear acceptable in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client/InFutureCheck.hs / HeaderArrivalException
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing.
- Exploit idea: Drive `HeaderArrivalException` in `Ouroboros.Consensus.MiniProtocol.ChainSync.Client.InFutureCheck` through the production entrypoint using future headers queued until slot becomes current; verify whether the path can make an invalid block or ledger state appear acceptable before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Disconnect/reconnect and Genesis sync transitions must not leave stale peer state that affects chain selection.
- Expected Cardano/Intersect impact: Potential High if adversarial peer scheduling makes honest nodes prefer different chains or starves valid block processing.
- Fast validation: Create an io-sim network with malicious and honest peers delivering headers, blocks, rollbacks, and disconnects in adversarial order.
