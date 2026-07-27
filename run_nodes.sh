#!/bin/bash
set -e

# Cleanup previous state
rm -rf ./data/node1.db ./data/node2.db
rm -f ./data/validators.json

# Create validators config
mkdir -p ./data
cat << 'JSON' > ./data/validators.json
{
  "validators": [
    "12D3KooWNode1ValidatorAddress12345"
  ]
}
JSON

echo "============================================="
echo "To run the validator node (Node 1):"
echo "cargo run -- --port 4001 --db-path ./data/node1.db --consensus poa --validators-file ./data/validators.json"
echo ""
echo "To run the observer node (Node 2) syncing to Node 1:"
echo "cargo run -- --port 4002 --db-path ./data/node2.db --consensus poa --validators-file ./data/validators.json --dial /ip4/127.0.0.1/tcp/4001"
echo "============================================="
echo ""
echo "Or run them automatically now (Node 1 in background, Node 2 in foreground for logs)? [y/N]"
