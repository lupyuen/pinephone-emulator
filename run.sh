#!/usr/bin/env bash

set -e  # Exit when any command fails
set -x  # Echo commands

cargo run | grep call_graph | colrm 1 13 \
  >nuttx-boot-flow.mmd

## Convert the Mermaid Flowchart to PDF, SVG and PNG
sudo docker pull minlag/mermaid-cli

sudo docker run \
  --rm -u `id -u`:`id -g` -v \
  .:/data minlag/mermaid-cli \
  --configFile="mermaidRenderConfig.json" \
  -i nuttx-boot-flow.mmd \
  -o nuttx-boot-flow.pdf

sudo docker run \
  --rm -u `id -u`:`id -g` -v \
  .:/data minlag/mermaid-cli \
  --configFile="mermaidRenderConfig.json" \
  -i nuttx-boot-flow.mmd \
  -o nuttx-boot-flow.svg

sudo docker run \
  --rm -u `id -u`:`id -g` -v \
  .:/data minlag/mermaid-cli \
  --configFile="mermaidRenderConfig.json" \
  -i nuttx-boot-flow.mmd \
  -o nuttx-boot-flow.png

exit

## Publish to crates.io
rm nuttx-boot-flow.svg
rm nuttx/nuttx.S
cargo publish
