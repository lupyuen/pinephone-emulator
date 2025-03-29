#!/usr/bin/env bash

set -e  # Exit when any command fails
set -x  # Echo commands

cargo run | grep call_graph | colrm 1 13 \
  >nuttx-boot-flow.mmd

## Convert the Mermaid Flowchart to PDF
sudo docker pull minlag/mermaid-cli
sudo docker run \
  --rm -u `id -u`:`id -g` -v \
  .:/data minlag/mermaid-cli \
  --configFile="mermaidRenderConfig.json" \
  -i nuttx-boot-flow.mmd \
  -o nuttx-boot-flow.pdf
