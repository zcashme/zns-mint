# Running testnet

SSH to the machine. The reset command runs on the host. Start the guest from the tmux session so closing the SSH window does not stop it.

```bash
sudo /home/ubuntu/zns-host-reset.sh
tmux attach
```

In that tmux window:

```bash
/usr/local/bin/zns-guest-testnet
```

The script starts Zebra and the keygen ceremony. Fund the address it prints. That is the only manual step. When the payment is in, the ceremony finishes and the script starts the mint.
