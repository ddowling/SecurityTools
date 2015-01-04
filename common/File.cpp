/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
 * File        : File
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : Helper functions for working with files
 */
#include "File.h"
#include <fstream>

String File::findOnPath(const String &colon_path, const String &file)
{
    StringVector path = split_string(colon_path, ":");

    return findOnPath(path, file);
}

String File::findOnPath(const StringVector &path, const String &file)
{
    StringVector::const_iterator iter;
    for(iter = path.begin(); iter != path.end(); ++iter)
    {
	String p = (*iter) + "/" + file;

	FILE *fd = fopen(p.c_str(), "r");

	if (fd != 0)
	{
	    fclose(fd);
	    return p;
	}
    }

    return "";
}

size_t File::getSize(const String &filename)
{
    std::ifstream file(filename.c_str(),
		       std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
        return file.tellg();
    else
    	return 0;
}

String File::readToString(const String &filename)
{
    std::ifstream file (filename.c_str(),
			std::ios::in |
			std::ios::binary |
			std::ios::ate);
    if (file.is_open())
    {
        size_t len = file.tellg();

	String s;
	s.resize(len);

	file.seekg (0, std::ios::beg);
	// FIXME What is the clean way to do this?
	file.read((char *)s.data(), len);
	file.close();

	return s;
    }
    else
    {
        // FIXME exception
        "";
    }
}

String File::getExtension(const String &filename)
{
    size_t p = filename.rfind('.');
    if (p == String::npos)
        return "";
    else
    	return filename.substr(p+1);
}
