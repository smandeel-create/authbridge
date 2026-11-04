#!/bin/sh
# Compiles the macOS crypto harness against ../ABCrypto.swift and writes vectors.json.
set -e
cd "$(dirname "$0")"
OUT="$(mktemp -d)"
# ABCrypto.swift must not be the main file; the harness uses top-level code, so name it main.swift.
cp crypto-check.swift "$OUT/main.swift"
swiftc -O -o "$OUT/crypto-check" "$OUT/main.swift" ../ABCrypto.swift
"$OUT/crypto-check" > vectors.json
rm -rf "$OUT"
echo "wrote $(pwd)/vectors.json"
