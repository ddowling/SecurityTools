/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : Table.h
 *
 * Author      : Denis Dowling
 * Created     : 7/12/2009
 *
 * Description : Helper functions to wrap blocks of text
 */
#ifndef WORD_WRAP_H
#define WORD_WRAP_H

#include "String.h"

StringVector wordWrap(const String &str, int max_width);

// Perform the initial word wrap and then keep reducing the columns until
// the line count goes up. In this way we use first minimum lines and then
// the minimum columns for this number of lines
StringVector wordWrapOptimum(const String &str, int max_width);

int lines(const StringVector &sv);
int columns(const StringVector &sv);

#endif
