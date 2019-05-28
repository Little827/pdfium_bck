#!/bin/bash
#
# Generate a chart of dependencies and includes in "dot" format.
# Invoke in pdfium/ top-level directory

TOPS="core fpdfsdk fxbarcode fxjs xfa"

function crunch {
FILES=`find $1 -name BUILD.gn`
echo '  edge [color=black,constraint=true]'
for FILE in $FILES; do
    DIR=`dirname $FILE`
    gn desc out/Asan $DIR deps | grep -v matches | sed "s|..\\(.*\\):.*|  \"$DIR\" -> \"\\1\"|"
done
echo '  edge [color=red,constraint=false]'
for FILE in $FILES; do
    DIR=`dirname $FILE`
    gn desc out/Asan $DIR allow_circular_includes_from | grep -v matches | sed "s|..\\(.*\\):.*|  \"\\1\" -> \"$DIR\"|"
done
}

echo 'digraph FRED {'
echo '  node [shape=rectangle]'
for TOP in $TOPS; do
crunch $TOP
done
echo '}'
