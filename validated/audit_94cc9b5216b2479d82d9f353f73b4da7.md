Looking at the external report's vulnerability class — **funds permanently frozen when sent to a contract before a required initialization state exists** — I need to find an analog in the NEAR Omni Bridge where tokens can be accepted and permanently locked before some prerequisite state is set up.

Let me examine the token locking mechanism and the `ft_on_transfer` entry point.