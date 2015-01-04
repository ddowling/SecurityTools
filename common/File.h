/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : ForensicTools
 * File        : File
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : Helper functions for working with files
 */
#ifndef FILE_H
#define FILE_H

#include "String.h"

class File
{
 public:
    // Return the full path name of a file on the given path. If file cannot be
    // found then return the empty string
    static String findOnPath(const String &colon_path, const String &file);
    static String findOnPath(const StringVector &path, const String &file);

    static size_t getSize(const String &filename);

    static String readToString(const String &filename);
    static String getExtension(const String &filename);
};

#endif
