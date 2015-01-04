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
#include "WordWrap.h"

StringVector wordWrap(const String &str, int max_width)
{
    StringVector res;

    StringVector lines = split_string(str, "\n");

    if (max_width < 0)
	return lines;

    int num_lines = lines.size();

    for(int i = 0; i < num_lines; i++)
    {
	String line;

	StringVector words = split_string(lines[i], " \t");

	int num_words = words.size();
	for(int j = 0; j < num_words; j++)
	{
	    String word = words[j];
	    if ((int)line.size() + (int) word.size() < max_width)
	    {
		if (line.size() != 0)
		    line += " ";

		line += word;
	    }
	    else
	    {
		if (line.size() != 0)
		{
		    res.push_back(line);
		    line = "";
		}

		line = word;

		// Keep splitting the current line until it fits
		while ((int)line.size() > max_width)
		{
		    res.push_back(line.substr(0, max_width));

		    line = line.substr(max_width);
		}
	    }
	}
	if (line.size() > 0)
	    res.push_back(line);
    }

    return res;
}

// Perform the initial word wrap and then keep reducing the columns until
// the line count goes up. In this way we use first minimum lines and then
// the minimum columns for this number of lines
StringVector wordWrapOptimum(const String &str, int max_width)
{
    StringVector ww = wordWrap(str, max_width);
    int num_lines = ww.size();
    if (num_lines <= 1)
	return ww;

    int width = max_width - 1;
    while(width > 0)
    {
	ww = wordWrap(str, width);
	if ((int)ww.size() > num_lines)
	    break;

	width--;
    }

    width++;
    return wordWrap(str, width);
}

int lines(const StringVector &sv)
{
    return sv.size();
}

int columns(const StringVector &sv)
{
    size_t c = 0;
    for (size_t i = 0; i < sv.size(); i++)
    {
	if (sv[i].size() > c)
	    c = sv[i].size();
    }

    return c;
}
