Looking at the external report's vulnerability class — **missing validation of an externally-supplied reference before using it in a security-critical computation** — I need to find an analog in Ouroboros Consensus where a peer-supplied object is accepted and used without being checked against a known-valid set.

Let me search for the most relevant code paths.