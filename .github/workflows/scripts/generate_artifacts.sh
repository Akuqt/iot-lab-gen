#!/bin/bash
set -e

echo "Creating artifacts directory..."

mkdir -p artifacts

echo "Generating iot-lab-gen artifact..."

ARTIFACT_DIR="iot-lab-gen"
mkdir -p "$ARTIFACT_DIR"

cp data/iot.json "$ARTIFACT_DIR/"
cp src/setup.sh "$ARTIFACT_DIR/"

tar -czvf artifacts/iot-lab-gen.tgz "$ARTIFACT_DIR"

rm -rf "$ARTIFACT_DIR"

echo "Artifact generated at artifacts/iot-lab-gen.tgz"
