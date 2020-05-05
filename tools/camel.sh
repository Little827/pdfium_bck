#!/bin/bash

FILES=`git grep -l '\bm_' $1`
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]*\)/\L\2_\3_\4_\5_\6_\7_/g' $FILES
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]*\)/\L\2_\3_\4_\5_\6_/g' $FILES
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]*\)/\L\2_\3_\4_\5_/g' $FILES
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]*\)/\L\2_\3_\4_/g' $FILES
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]\+\)\([A-Z]\+[a-z0-9_]*\)/\L\2_\3_/g' $FILES
sed -i 's/\bm_\([bcefinps]\|dw\|bs\|sz\|\)\([A-Z]\+[a-z0-9_]*\)/\L\2_/g' $FILES

sed -i 's/\bm_\(\w\+\)\b/\L\1_/g' $FILES

