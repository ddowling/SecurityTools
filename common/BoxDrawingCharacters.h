/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : BoxDrawingCharacters.h
 *
 * Author      : Denis Dowling
 * Created     : 8/12/2009
 *
 * Description : ASCII Art line drawing characters
 */
#ifndef BOX_DRAWING_H
#define BOX_DRAWING_H

#include "String.h"

// Define the box drawing characters in terms of these primatives.
// We OR the primatives together to.
// Make the desired character. This makes it easy to connect lines to
// existing boxes and is shorter than enumerating the common 40 different
// box drawing character names. Note not all combinations of will result in
// a valid line drawing character. Generally need at least 2 bits set in a
// character.
enum LineSectionType
{
    B_LIGHT_UP = 1 << 0,
    B_LIGHT_DOWN = 1 << 1,
    B_LIGHT_VERTICAL = B_LIGHT_UP | B_LIGHT_DOWN,
    B_LIGHT_LEFT = 1 << 2,
    B_LIGHT_RIGHT = 1 << 3,
    B_LIGHT_HORIZONTAL = B_LIGHT_LEFT | B_LIGHT_RIGHT,

    B_DOUBLE_UP = 1 << 4,
    B_DOUBLE_DOWN = 1 << 5,
    B_DOUBLE_VERTICAL = B_DOUBLE_UP | B_DOUBLE_DOWN,
    B_DOUBLE_LEFT = 1 << 6,
    B_DOUBLE_RIGHT = 1 << 7,
    B_DOUBLE_HORIZONTAL = B_DOUBLE_LEFT | B_DOUBLE_RIGHT,
};

String getLineStr(int line_type, int num = 1);

enum CodePage
{
    CP_ASCII,
    CP_UTF8,
    CP_MSDOS,
    CP_VT100 // Not really a code page but outputs the excape sequences
};

void setCodePage(CodePage cp);
CodePage getCodePage();

bool setCodePageFromString(String str);

#endif
