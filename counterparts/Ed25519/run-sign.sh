#!/bin/bash

msgsizes=(32 64 128 256 512 1024 2048 4096 8192)

gcc sign.c -lsodium -o sign
for size in "${msgsizes[@]}"; do
    echo "MSGSIZE = $size"
    ./sign $size
    echo ""
done
