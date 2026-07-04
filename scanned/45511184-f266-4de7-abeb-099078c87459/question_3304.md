# Q3304: future headers queued until slot becomes current in mkGenesisNodeKernelArgs

## Question
Can an unprivileged attacker reach mkGenesisNodeKernelArgs with future headers queued until slot becomes current and normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing, then confuse header/body, era, or storage context in production Ouroboros consensus behavior?

## Target
- File/function: ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Node/Genesis.hs / mkGenesisNodeKernelArgs
- Entrypoint: Unprivileged node-to-node or node-to-client peer sends supported protocol messages, rollbacks, block bodies, queries, or object-diffusion data in adversarial order.
- Attacker controls: normal adversarial network scheduling, delayed data, replayed announcements, fork delivery order, and diffusion-to-consensus callback timing.
- Exploit idea: Drive `mkGenesisNodeKernelArgs` in `Ouroboros.Consensus.Node.Genesis` through the production entrypoint using future headers queued until slot becomes current; verify whether the path can confuse header/body, era, or storage context before all consensus, ledger, storage, and era-specific guards have succeeded.
- Invariant to test: Disconnect/reconnect and Genesis sync transitions must not leave stale peer state that affects chain selection.
- Expected Cardano/Intersect impact: Potential Medium if an unprivileged peer can cause repeated expensive consensus work with near-valid data without flood-style DoS.
- Fast validation: Add a ChainSync/BlockFetch integration test with withheld bodies and a complete competing chain.
