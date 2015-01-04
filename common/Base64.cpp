/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : ForensicTools
 * File        : Base64
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : Encode and decode a string in Base64 format
 */
#include "Base64.h"
#include "Assert.h"

char Base64::encodeChar(unsigned char b)
{
    if (b < 26)
	return 'A' + b;

    if (b < 52)
	return 'a' + (b-26);

    if (b < 62)
	return '0' + (b-52);

    if (b == 62)
	return '+';

    if (b == 63)
	return '/';

    assert(0 /* Cannot encode */);
    return 0;
}

unsigned char Base64::decodeChar(char c)
{
    if (c >= 'A' && c <= 'Z')
	return c - 'A';

    if (c >= 'a' && c <= 'z')
	return c - 'a' + 26;

    if (c >= '0' && c <= '9')
	return c - '0' + 52;

    if (c == '+')
	return 62;

    if (c == '/' || c == '=')
	return 63;

    ASSERT(0 /* Invalid base64 char */);

    return 0;
}

bool Base64::validChar(char c)
{
    if (c >= 'A' && c <= 'Z')
	return true;

    if (c >= 'a' && c <= 'z')
	return true;

    if (c >= '0' && c <= '9')
	return true;

    if (c == '+')
	return true;

    if (c == '/')
	return true;

    if (c == '=')
	return true;

    return false;
}

String Base64::encode(const String &raw, bool break_line)
{
    String str;

    const size_t chars_per_line = 64 * 3 / 4;

    for (size_t i = 0;i < raw.size();i += 3)
    {
	unsigned char by1 = 0, by2 = 0, by3 = 0;
	by1 = raw[i];
	if (i+1 < raw.size())
	    by2 = raw[i+1];

	if (i+2 < raw.size())
	    by3 = raw[i+2];

	unsigned char by4 = by1>>2;
	unsigned char by5 = ((by1 & 0x3)<<4) | (by2>>4);
	unsigned char by6 = ((by2 & 0xf)<<2) | (by3>>6);
	unsigned char by7 = by3 & 0x3f;

	str += encodeChar(by4);
	str += encodeChar(by5);

	if (i+1 < raw.size())
	    str += encodeChar(by6);
	else
	    str += "=";

	if (i+2 < raw.size())
	    str += encodeChar(by7);
	else
	    str += "=";

	if (break_line && ((i+3) % chars_per_line) == 0)
	    str += "\n";
    }

    return str;
}

String Base64::decode(const String &enc)
{
    String str;
    for (size_t j = 0;j < enc.size(); j++)
    {
	if (validChar(enc[j]))
	    str += enc[j];
    }

    String res;

    for (size_t i = 0; i < str.size(); i+=4)
    {
	char c1 = 'A', c2 = 'A', c3 = 'A', c4 = 'A';
	c1 = str[i];
	if (i+1 < str.size())
	    c2 = str[i+1];

	if (i+2 < str.size())
	    c3 = str[i+2];

	if (i+3 < str.size())
	    c4 = str[i+3];

	unsigned char by1 = decodeChar(c1);
	unsigned char by2 = decodeChar(c2);
        unsigned char by3 = decodeChar(c3);
	unsigned char by4 = decodeChar(c4);

	res.push_back((by1<<2)|(by2>>4));

	if (c3 != '=')
	    res.push_back(((by2&0xf)<<4)|(by3>>2));

	if (c4 != '=')
	    res.push_back(((by3&0x3)<<6)|by4);
    }

    return res;
}
