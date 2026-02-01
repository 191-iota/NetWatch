#!/bin/bash
set -e

source .env

cross build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/netwatch ${PI_USER}@${PI_HOST}:${PI_PATH}/
ssh ${PI_USER}@${PI_HOST} "sudo setcap cap_net_raw=eip ${PI_PATH}/netwatch"
echo "deployed. run: ssh ${PI_USER}@${PI_HOST} '${PI_PATH}/netwatch'"
```

Add to `.gitignore`:
```
.env
