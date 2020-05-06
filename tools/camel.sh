#!/bin/bash
#
# Convert m_pPdfiumStyle members from CamelCase to chromium_style_
#

FILES=`git grep -l '\bm_' $1`
DISCARD='\bm_\([bcefinps]\|dw\|bs\|ws\|sz\|rt\|rg\|\)'
LEAD='\([A-Z]\+[a-z0-9_]\+\)'
LAST='\([A-Z]\+[a-z0-9_]*\)'
ONE_HUMP="$DISCARD$LAST"
TWO_HUMP="$DISCARD$LEAD$LAST"
THREE_HUMP="$DISCARD$LEAD$LEAD$LAST"
FOUR_HUMP="$DISCARD$LEAD$LEAD$LEAD$LAST"
FIVE_HUMP="$DISCARD$LEAD$LEAD$LEAD$LEAD$LAST"
SIX_HUMP="$DISCARD$LEAD$LEAD$LEAD$LEAD$LEAD$LAST"
ONE_DASH='\L\2_'
TWO_DASH='\L\2_\3_'
THREE_DASH='\L\2_\3_\4_'
FOUR_DASH='\L\2_\3_\4_\5_'
FIVE_DASH='\L\2_\3_\4_\5_\6_'
SIX_DASH='\L\2_\3_\4_\5_\6_\7_'

sed -i "s/$SIX_HUMP/$SIX_DASH/g" $FILES
sed -i "s/$FIVE_HUMP/$FIVE_DASH/g" $FILES
sed -i "s/$FOUR_HUMP/$FOUR_DASH/g" $FILES
sed -i "s/$THREE_HUMP/$THREE_DASH/g" $FILES
sed -i "s/$TWO_HUMP/$TWO_DASH/g" $FILES
sed -i "s/$ONE_HUMP/$ONE_DASH/g" $FILES

sed -i 's/\bm_\(\w\+\)\b/\L\1_/g' $FILES
