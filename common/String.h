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
#ifndef STRING_H
#define STRING_H

#include <string>
typedef std::string String;
#include <sstream>
typedef std::stringstream StringStream;

#include <vector>
typedef std::vector<String> StringVector;

// Some helper functions missing from std::string
const String white_space = " \t\r\n";

StringVector split_string(const String &str, const String &sep = white_space);

String trim_right(const String &source , const String& t = white_space);
String trim_left( const String& source, const String& t = white_space);
String trim(const String& source, const String& t = white_space);

void to_upper(String &str);
String upper(const String &source);
void to_lower(String &str);
String lower(const String &source);

// Repeat the supplied string n times
String repeat(const String &str, int n);
#endif
