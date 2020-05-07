#!/bin/bash
#
# Convert m_pPdfiumStyle members from CamelCase to chromium_style_
#
set -v

DISCARD='\bm_\([bcefhinpsuw]\|dw\|bs\|ws\|sz\|rt\|rg\|cs\|rt\|rc\|mt\|pp\|\)'
KEEP='\bm_\([a-z]\+\)'
LEAD='\([A-Z]\+[a-z0-9_]\+\)'
LAST='\([A-Z]\+[a-z0-9_]*\)'

ONE_HUMP="$LAST"
TWO_HUMP="$LEAD$LAST"
THREE_HUMP="$LEAD$LEAD$LAST"
FOUR_HUMP="$LEAD$LEAD$LEAD$LAST"
FIVE_HUMP="$LEAD$LEAD$LEAD$LEAD$LAST"
SIX_HUMP="$LEAD$LEAD$LEAD$LEAD$LEAD$LAST"

ONE_DASH='\2_'
TWO_DASH='\2_\3_'
THREE_DASH='\2_\3_\4_'
FOUR_DASH='\2_\3_\4_\5_'
FIVE_DASH='\2_\3_\4_\5_\6_'
SIX_DASH='\2_\3_\4_\5_\6_\7_'

FILES=`git grep -l '\bm_' $1`

sed -i "s/$DISCARD$SIX_HUMP/\L$SIX_DASH/g" $FILES
sed -i "s/$DISCARD$FIVE_HUMP/\L$FIVE_DASH/g" $FILES
sed -i "s/$DISCARD$FOUR_HUMP/\L$FOUR_DASH/g" $FILES
sed -i "s/$DISCARD$THREE_HUMP/\L$THREE_DASH/g" $FILES
sed -i "s/$DISCARD$TWO_HUMP/\L$TWO_DASH/g" $FILES
sed -i "s/$DISCARD$ONE_HUMP/\L$ONE_DASH/g" $FILES

sed -i "s/$KEEP$SIX_HUMP/\L\1_$SIX_DASH/g" $FILES
sed -i "s/$KEEP$FIVE_HUMP/\L\1_$FIVE_DASH/g" $FILES
sed -i "s/$KEEP$FOUR_HUMP/\L\1_$FOUR_DASH/g" $FILES
sed -i "s/$KEEP$THREE_HUMP/\L\1_$THREE_DASH/g" $FILES
sed -i "s/$KEEP$TWO_HUMP/\L\1_$TWO_DASH/g" $FILES
sed -i "s/$KEEP$ONE_HUMP/\L\1_$ONE_DASH/g" $FILES

sed -i 's/\bm_\(\w\+\)\b/\L\1_/g' $FILES
