/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : String
 *
 * Author      : Denis Dowling
 * Created     : 6/5/2009
 *
 * Description : String helper functions
 */
#include "String.h"
#include <algorithm>

StringVector split_string(const String &str, const String &sep)
{
    StringVector ret;

    size_t p = 0;
    while(true)
    {
        size_t i = str.find_first_of(sep, p);
	if (i == std::string::npos)
	    break;

	String token = str.substr(p, i - p);
	ret.push_back(token);
	p = i + 1;
    }

    if (p < str.size())
    {
	String token = str.substr(p);
	ret.push_back(token);
    }

    return ret;
}

String trim_right(const String &source , const String& t)
{
    String str = source;
    return str.erase( str.find_last_not_of(t) + 1);
}

String trim_left( const String& source, const String& t)
{
    String str = source;
    return str.erase(0 , source.find_first_not_of(t) );
}

String trim(const String& source, const String& t)
{
    String str = source;
    return trim_left( trim_right( str , t) , t );
}

void to_upper(String &str)
{
    std::transform(str.begin(), str.end(), str.begin(), toupper);
}

String upper(const String &source)
{
    String str = source;
    to_upper(str);
    return str;
}

void to_lower(String &str)
{
    std::transform(str.begin(), str.end(), str.begin(), tolower);
}

String lower(const String &source)
{
    String str = source;
    to_lower(str);
    return str;
}

// Repeat the supplied string n times
String repeat(const String &str, int n)
{
    String ret;

    for(int i = 0; i < n; i++)
	ret += str;

    return ret;
}

