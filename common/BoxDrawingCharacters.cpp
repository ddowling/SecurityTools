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
#include "BoxDrawingCharacters.h"
#include <stdio.h>

static CodePage codePage = CP_ASCII;

// MSDOS should really be called Code page 437. Set this in
// the terminal to get line drawing characters
struct Table
{
    int type;
    char ascii;
    char msdos;
    int unicode;
    int vt100;
};

// Character Set Encodings
// Code, ASCII Equiv, MSDOS, UNICODE
static struct Table table[] = {
    { B_LIGHT_VERTICAL, '|', 0xb3, 0x2502, 0x78 },
    { B_LIGHT_HORIZONTAL, '-', 0xc4, 0x2500, 0x71 },
    { B_LIGHT_VERTICAL | B_LIGHT_HORIZONTAL, '+', 0xc5, 0x253c, 0x6e },
    { B_LIGHT_LEFT | B_LIGHT_UP, '+', 0xd9, 0x2518, 0x6a },
    { B_LIGHT_LEFT | B_LIGHT_DOWN, '+', 0xbf, 0x2510, 0x6b },
    { B_LIGHT_RIGHT | B_LIGHT_UP, '+', 0xc0, 0x2514, 0x6d },
    { B_LIGHT_RIGHT | B_LIGHT_DOWN, '+', 0xda, 0x250c, 0x6c },
    { B_LIGHT_VERTICAL | B_LIGHT_LEFT, '+', 0xb4, 0x2524, 0x75 },
    { B_LIGHT_VERTICAL | B_LIGHT_RIGHT, '+', 0xc3, 0x251c, 0x74 },
    { B_LIGHT_HORIZONTAL | B_LIGHT_UP, '+', 0xc1, 0x2534, 0x76 },
    { B_LIGHT_HORIZONTAL | B_LIGHT_DOWN, '+', 0xc2, 0x252c, 0x77 },

    { B_DOUBLE_VERTICAL, '|', 0xba, 0x2551, 0x78 },
    { B_DOUBLE_HORIZONTAL, '=',0xcd, 0x2550, 0x71 },
    { B_DOUBLE_VERTICAL | B_DOUBLE_HORIZONTAL, '+', 0xce, 0x256c, 0x6e },
    { B_DOUBLE_LEFT | B_DOUBLE_UP, '+', 0xbc, 0x255d, 0x6a },
    { B_DOUBLE_LEFT | B_DOUBLE_DOWN, '+', 0xbb, 0x2557, 0x6b },
    { B_DOUBLE_RIGHT | B_DOUBLE_UP, '+', 0xc8, 0x255a, 0x6d },
    { B_DOUBLE_RIGHT | B_DOUBLE_DOWN, '+', 0xc9, 0x2554, 0x6c },
    { B_DOUBLE_VERTICAL | B_DOUBLE_LEFT, '+', 0xb9, 0x2563, 0x75 },
    { B_DOUBLE_VERTICAL | B_DOUBLE_RIGHT, '+', 0xcc, 0x2560, 0x74 },
    { B_DOUBLE_HORIZONTAL | B_DOUBLE_UP, '+', 0xca, 0x2569, 0x76 },
    { B_DOUBLE_HORIZONTAL | B_DOUBLE_DOWN, '+', 0xcb, 0x2566, 0x77 },

    { B_LIGHT_VERTICAL | B_DOUBLE_HORIZONTAL, '+', 0xd8, 0x256a, 0x6e },
    { B_LIGHT_VERTICAL | B_DOUBLE_LEFT, '+', 0xb5, 0x2561, 0x75 },
    { B_LIGHT_VERTICAL | B_DOUBLE_RIGHT, '+', 0xc6, 0x255e, 0x74 },
    { B_DOUBLE_VERTICAL | B_LIGHT_LEFT, '+', 0xb6, 0x2562, 0x75 },
    { B_DOUBLE_VERTICAL | B_LIGHT_RIGHT, '+', 0xc7, 0x255f, 0x74 },
    { B_DOUBLE_VERTICAL | B_LIGHT_HORIZONTAL, '+', 0xd7, 0x256b, 0x6e },
    { B_LIGHT_UP | B_DOUBLE_HORIZONTAL, '+', 0xcf, 0x2567, 0x76 },
    { B_LIGHT_DOWN | B_DOUBLE_HORIZONTAL, '+', 0xd1, 0x2564, 0x77 },
    { B_LIGHT_LEFT | B_DOUBLE_UP, '+', 0xbd, 0x255c, 0x6a },
    { B_DOUBLE_LEFT | B_LIGHT_UP, '+', 0xbe, 0x255b, 0x6a },
    { B_LIGHT_LEFT | B_DOUBLE_DOWN, '+', 0xb7, 0x2556, 0x6b },
    { B_DOUBLE_LEFT | B_LIGHT_DOWN, '+', 0xb8, 0x2555, 0x6b },
    { B_LIGHT_RIGHT | B_DOUBLE_UP, '+', 0xd3, 0x2559, 0x6d },
    { B_DOUBLE_RIGHT| B_LIGHT_UP, '+', 0xd4, 0x2558, 0x6d },
    { B_LIGHT_RIGHT | B_DOUBLE_DOWN, '+', 0xd6, 0x2553, 0x6c },
    { B_DOUBLE_RIGHT | B_LIGHT_DOWN, '+', 0xd5, 0x2552, 0x6c },
    { B_DOUBLE_HORIZONTAL | B_LIGHT_DOWN, '+', 0xd1, 0x2554, 0x77 },
    { B_LIGHT_HORIZONTAL | B_DOUBLE_DOWN, '+', 0xd2, 0x2555, 0x77 },
    { B_LIGHT_HORIZONTAL | B_DOUBLE_UP, '+', 0xd0, 0x2558, 0x77 },

};

static String utf8(int c)
{
    if (c > 0 && c <= 0x7f)
	return String(1, c);
    else if (c >= 0x80 && c <= 0x7ff)
    {
	String s;
	s.push_back(0xc0 | (c >> 6));
	s.push_back(0x80 | (c & 0x3f));
	return s;
    }
    else
    {
	String s;
	s.push_back(0xe0 | (c >> 12));
	s.push_back(0x80 | (c >> 6) & 0x3f);
	s.push_back(0x80 | (c & 0x3f));
	return s;
    }
}

String getLineStr(int line_type, int num)
{
    Table *t;
    for (t = table; t != table + sizeof(table)/sizeof(table[0]); t++)
    {
	if (t->type == line_type)
	{
	    switch (codePage)
	    {
	    case CP_ASCII:
		if (t->ascii != 0)
		    return String(num, t->ascii);
	    case CP_MSDOS:
		if (t->msdos != 0)
		    return String(num, t->msdos);
	    case CP_UTF8:
		if (t->unicode != 0)
		    // Encode to UTF8
		    return repeat(utf8(t->unicode), num);
	    case CP_VT100:
		//printf("VT100:%02x\n", t->vt100);
		if (t->vt100 != 0)
		    // Switch to alternate character set
		    return String(1, 0x0e) + // Switch to ALT character set
			String(num, t->vt100) +
			String(1, 0x0f); // Switch back to normal characters
	    }
	}
    }

    //fprintf(stderr, "Illegal box draw character %02x\n", line_type);

    return String(num, '*');
}

void setCodePage(CodePage cp)
{
    codePage = cp;
}

CodePage getCodePage()
{
    return codePage;
}

bool setCodePageFromString(String str)
{
    if (str == "ascii")
    {
	codePage = CP_ASCII;
	return true;
    }
    else if (str == "msdos" || str == "cp437")
    {
	codePage = CP_MSDOS;
	return true;
    }
    else if (str == "utf8")
    {
	codePage = CP_UTF8;
	return true;
    }
    else if (str == "vt100")
    {
	codePage = CP_VT100;
	return true;
    }

    return false;
}
