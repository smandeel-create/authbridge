#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
swiftc -O authbridge-se.swift -o bin/authbridge-se
codesign --force --sign - bin/authbridge-se
echo "built $(pwd)/bin/authbridge-se"
