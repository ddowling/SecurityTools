/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : test_line_draw
 *
 * Author      : Denis Dowling
 * Created     : 8/12/2009
 *
 * Description : ASCII Art line drawing characters
 */
#include <stdio.h>
#include "String.h"

String unicodeToUTF8(int *utf16_str, int len)
{
    String out;

    for(int i = 0; i < len; i++)
    {
	int c = utf16_str[i];
	if (c <= 0x007F)
	    out.push_back(c);
	else if (c > 0x07FF)
	{
	    out.push_back(0xE0 | ((c >> 12) & 0x0F));
	    out.push_back(0x80 | ((c >>  6) & 0x3F));
	    out.push_back(0x80 | ((c >>  0) & 0x3F));
	}
	else
	{
	    out.push_back(0xC0 | ((c >>  6) & 0x1F));
	    out.push_back(0x80 | ((c >>  0) & 0x3F));
	}
    }

    return out;
}

int main()
{
#if 0
    for (int i = 0x2500; i < 0x257f; i++)
    {
	String s = unicodeToUTF8(&i, 1);

	printf("h(%04x) = %s\n", i, s.c_str());
    }
#endif

    for (int i = 0x0; i < 0xff; i++)
    {
        char s[20];
	int p = 0;
	s[p++] = 0x1b; // ESC
	s[p++] = '(';
	s[p++] = '0';
	s[p++] = i;
	s[p++] = 0;

	printf("h(%04x) = %s\n", i, s);
    }

}
