#!/bin/bash

git clone https://github.com/neo4j-labs/neodash.git
sed -i 's\Warning: NeoDash is running with a plaintext password in config.json.\\g' neodash/src/dashboard/Dashboard.tsx

docker rmi pythonloader
docker rmi visualizer
docker compose --env-file ../.env -f ../compose.yml up -d
rm -rf neodash
