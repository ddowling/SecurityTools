/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
 * File        : Base64
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : Encode and decode a string in Base64 format
 */
#ifndef BASE64_H
#define BASE64_H

#include "String.h"

class Base64
{
 public:
    static String encode(const String &raw, bool break_line = false);

    static String decode(const String &enc);

 protected:
    static char encodeChar(unsigned char b);
    static unsigned char decodeChar(char c);

    static bool validChar(char c);

};

#endif
