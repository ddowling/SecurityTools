/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
 * File        : TextProperty
 *
 * Author      : Denis Dowling
 * Created     : 7/12/2009
 *
 * Description : class to implement helper functions to get various properties on text
 */
#include "TextProperty.h"

String red(const String &s)
{
    return "<red>" + s + "</red>";
}

String green(const String &s)
{
    return "<green>" + s + "</green>";
}

String blue(const String &s)
{
    return "<blue>" + s + "</blue>";
}

String bold(const String &s)
{
    return "<b>" + s + "</b>";
}

