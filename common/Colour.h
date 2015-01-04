/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : Colour.h
 *
 * Author      : Denis Dowling
 * Created     : 9/12/2009
 *
 * Description : Colour definitions
 */
#ifndef COLOUR_H
#define COLOUR_H

#include "String.h"

enum Colour
{
    COL_DEFAULT,
    COL_RED,
    COL_GREEN,
    COL_BLUE,
};

// Control if ANSI colour support is to be enabled
void setANSIColour(bool s);

String setTextColour(Colour c, const String &str);
String setHTMLColour(Colour c, const String &str);

#endif
