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
#include "Colour.h"

static bool ansiColour = false;

// Control if ANSI colour support is to be enabled
void setANSIColour(bool s)
{
    ansiColour = s;
}

String setTextColour(Colour c, const String &str)
{
    if (!ansiColour)
        return str;

    // ANSI Escape sequences
    const char *c_reset = "[0m";
    const char *c_red = "[31m";
    const char *c_blue = "[34m";
    const char *c_green = "[32m";

    String ret;
    switch(c)
    {
    case COL_RED:
	ret = c_red;
	break;
    case COL_GREEN:
	ret = c_green;
	break;
    case COL_BLUE:
	ret = c_blue;
	break;
    default:
	return str;
    }

    ret += str + c_reset;

    return ret;
}

String setHTMLColour(Colour c, const String &str)
{
    const char *colour_code;
    switch(c)
    {
    case COL_RED:
	colour_code = "#FF0000";
	break;
    case COL_GREEN:
	colour_code = "#00FF00";
	break;
    case COL_BLUE:
	colour_code = "#0000FF";
	break;
    default:
	return str;
    }

    String ret = String("<font color=\"") + colour_code + "\">";
    ret += str;
    ret += "</font>";

    return ret;
}
