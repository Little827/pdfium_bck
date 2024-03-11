#!/bin/bash
#
# Copyright 2024 The PDFium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Script to fetch diffing images from pdfium-gold.
#
if [ $# -ne 2 ] ; then
    echo "Typical usage: golden.sh skia_win https://logs.chromium.org/logs/pdfium/buildbucket/cr-buildbucket/8753735982839766497/+/u/corpus_tests__oneshot_rendering_enabled_/stdout?format=raw"
    exit 1
fi

# Fetch test results
curl -o ./$1.log $2

# Fetch diffing images from the gold server
TESTS=`grep 'cache[/\\]builder[/\\]' ./$1.log | grep -v Failed | grep -ho '[A-Za-z0-9_]*[.]pdf' | sed 's/\(.*\)[.]pdf/\1/'`
for TEST in $TESTS ; do
    IDX=0
    while true ; do
        REV=`grep "^Untriaged.*$TEST.pdf.$IDX" ./$1.log | sed 's/^.*digest=\([0-9a-f]*\).*$/\1/'`
        if [ -z "$REV" ] ; then
            break
        fi
        curl -o ./${TEST}_expected_$1.pdf.$IDX.png https://pdfium-gold.skia.org/img/images/$REV.png
        optipng ./${TEST}_expected_$1.pdf.$IDX.png
        IDX=$(($IDX + 1))
    done
done
