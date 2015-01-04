/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
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

