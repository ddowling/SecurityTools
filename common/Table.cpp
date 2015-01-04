/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : Table.h
 *
 * Author      : Denis Dowling
 * Created     : 6/5/2009
 *
 * Description : A Table that can be rendered into a number of different formats
 */
#include "Table.h"
#include "WordWrap.h"
#include "BoxDrawingCharacters.h"
#include "TextProperty.h"
#include <algorithm>

Table::Table()
{
    tableClass = "reporttable";
}

// Add a caption to the table
void Table::addCaption(String caption_)
{
    caption = caption_;
}

// Add a heading row to a table
void Table::addHeadingRow()
{
    Row r;
    r.isHeading = true;

    rows.push_back(r);
}

// Add a new row to a table
void Table::addRow()
{
    Row r;
    r.isHeading = false;

    rows.push_back(r);
}

void Table::addCell(String contents)
{
    Row &r = rows.back();

    Cell c;
    c.contents = contents;
    c.colour = COL_DEFAULT;

    r.cells.push_back(c);
}

void Table::setCellColour(Colour colour)
{
    Row &r = rows.back();

    // Ignore if no cells
    if (r.cells.size() == 0)
	return;

    Cell &c = r.cells.back();
    c.colour = colour;
}

const int pad = 1;
const int desired_screen_width = 80;

void Table::determineColumnWidths()
{
    colWidths.clear();
    int screen_width = desired_screen_width;

    // Determine the width of all of the columns
    RowVector::const_iterator row_iter;
    for(row_iter = rows.begin(); row_iter != rows.end(); ++row_iter)
    {
	const Row &r = *row_iter;

	// FIXME This is not the column width. Need to break into lines
	if (colWidths.size() < r.cells.size())
	    colWidths.resize(r.cells.size());

	CellVector::const_iterator cell_iter;
	int col_num;

	for(cell_iter = r.cells.begin(), col_num = 0; cell_iter != r.cells.end(); ++cell_iter, col_num++)
	{
	    const Cell &c = *cell_iter;

	    if ((int)c.contents.size() + 2 * pad > colWidths[col_num])
		colWidths[col_num] = c.contents.size() + 2 * pad;
	}
    }

    // Calculate a fair column usage
    int num_columns = colWidths.size();
    int fair_usage = screen_width / num_columns;
    // If columns are going to be too small then blow out the total width
    if (fair_usage < 5)
    {
	fair_usage = 5;
	screen_width = fair_usage * num_columns;
    }

    // Iterate over all columns and sum up the widths of all columns
    // Need to include extra width of the column dividers
    int total_width = 1;
    IntVector::iterator iter;
    for(iter = colWidths.begin(); iter != colWidths.end(); ++iter)
	total_width += *iter + 1;

    if (total_width > screen_width)
    {
	// Sort the columns widths
	IntVector width_sorted = colWidths;
	std::sort(width_sorted.begin(), width_sorted.end());

	int width_left = screen_width - 1;
	int cols_left = num_columns;
	for(iter = width_sorted.begin(); iter != width_sorted.end(); ++iter)
	{
	    // Calculate a fair column usage for this and remaining columns
	    fair_usage = (width_left / cols_left) - 1;

	    // If current column width is greater than this fair usage then
	    // break
	    if ((*iter) > fair_usage)
		break;

	    width_left -= (*iter) + 1;
	    cols_left--;
	}

	// Now go through and scale all columns above the fair usage to the
	// fair usage value
	for(iter = colWidths.begin(); iter != colWidths.end(); ++iter)
	{
	    if (*iter > fair_usage)
		(*iter) = fair_usage;
	}
    }
}

void Table::wrapCells()
{
    // Determine the width of all of the columns
    RowVector::iterator row_iter;
    for(row_iter = rows.begin(); row_iter != rows.end(); ++row_iter)
    {
	Row &r = *row_iter;

	CellVector::iterator cell_iter;
	int col_num;
	for(cell_iter = r.cells.begin(), col_num = 0;
	    cell_iter != r.cells.end();
	    ++cell_iter, col_num++)
	{
	    Cell &c = *cell_iter;
	    int width = colWidths[col_num];

	    c.wrappedContents =
		    wordWrapOptimum(c.contents, width - 2 * pad);
	}
    }
}

void Table::determineRowHeights()
{
    // Determine the height of all of the rows
    RowVector::iterator row_iter;
    for(row_iter = rows.begin(); row_iter != rows.end(); ++row_iter)
    {
	Row &r = *row_iter;

	r.height = 1;

	CellVector::iterator cell_iter;
	int col_num;
	for(cell_iter = r.cells.begin(), col_num = 0; cell_iter != r.cells.end(); ++cell_iter, col_num++)
	{
	    Cell &c = *cell_iter;

	    int h = lines(c.wrappedContents);
	    if (h > r.height)
		r.height = h;
	}
    }
}

void Table::traverse(ReportVisitor &report_visitor)
{
    report_visitor.enterTable(*this);

    ReportElement::traverse(report_visitor);

    report_visitor.exitTable(*this);
}

String Table::addHRule(const Row &r, bool top, bool bottom)
{
    String hrule;

    for(size_t col_num = 0; col_num < colWidths.size(); col_num++)
    {
        int line_u;
        int line_d;
        int line_l;
        int line_r;

        line_u = B_LIGHT_UP;
        line_d = B_LIGHT_DOWN;

        if (r.isHeading)
        {
            line_l = B_DOUBLE_LEFT;
            line_r = B_DOUBLE_RIGHT;
        }
        else
        {
            line_l = B_LIGHT_LEFT;
            line_r = B_LIGHT_RIGHT;
        }

	// Left most cell must print left edge
	if (col_num == 0)
        {
            int l = line_r;
            if (!top)
                l |= line_u;
            if (!bottom)
                l |= line_d;

            hrule += getLineStr(l);
        }

        hrule += getLineStr(line_l | line_r, colWidths[col_num]);

        int l = line_l;
        if (!top)
            l |= line_u;
        if (!bottom)
            l |= line_d;
        if (col_num != colWidths.size() - 1)
            l |= line_r;

        hrule += getLineStr(l);
    }

    hrule += "\n";

    return hrule;
}

String Table::renderAsASCII(bool use_colour)
{
    determineColumnWidths();
    wrapCells();
    determineRowHeights();

    String table;

    size_t num_columns = colWidths.size();
    size_t num_rows = rows.size();

    for(size_t row = 0; row < num_rows; row++)
    {
	const Row &r = rows[row];

	// If first row
	if (row == 0)
	    table += addHRule(r, true, false);

	for (int line = 0; line < r.height; line++)
	{
	    for(size_t col_num = 0; col_num < num_columns; col_num++)
	    {
		if (col_num == 0)
		    // Left most cell must print left edge
		    table += getLineStr(B_LIGHT_VERTICAL);
		table += " ";

		String fmt;
		if (col_num < r.cells.size())
		{
		    const Cell &c = r.cells[col_num];

		    if (line < lines(c.wrappedContents))
			fmt = c.wrappedContents[line];

		    fmt.resize(colWidths[col_num] - 2 * pad, ' ');

		    if (use_colour && c.colour != COL_DEFAULT &&
			fmt.size() != 0)
			fmt = setTextColour(c.colour, fmt);
		}
		else
		    fmt.resize(colWidths[col_num] - 2 * pad, ' ');

		table += fmt;

		table += " ";
		table += getLineStr(B_LIGHT_VERTICAL);
	    }
	    table += "\n";
	}

	table += addHRule(r, false, row == num_rows - 1);
    }

    return table;
}

String Table::renderAsHTML()
{
    String table;
    String current_section;

    table = "<TABLE";
    if (tableClass.size() > 0)
	table += " CLASS=\"" + tableClass + "\"";
    table += ">\n";

    if (caption.size() > 0)
	table += "<CAPTION>" + caption + "</CAPTION>\n";

    size_t num_columns = 0;
    RowVector::const_iterator row_iter;
    for(row_iter = rows.begin(); row_iter != rows.end(); ++row_iter)
    {
	const Row &r = *row_iter;

	if (r.cells.size() > num_columns)
	    num_columns = r.cells.size();
    }

    int row_num;
    for(row_iter = rows.begin(), row_num = 0; row_iter != rows.end(); ++row_iter, row_num++)
    {
	const Row &r = *row_iter;

	String section;
	if (r.isHeading)
	    section = "THEAD";
	else
	    section = "TBODY";
	if (section != current_section)
	{
	    if (current_section.size() > 0)
		table += "</" + current_section + ">\n";

	    current_section = section;
	    table += "<" + current_section + ">\n";
	}

	if (row_num % 2 == 0)
	    table += "<TR class = \"evenrow\">";
	else
	    table += "<TR>";

	for(size_t col_num = 0; col_num < num_columns; col_num++)
	{
	    if (col_num < r.cells.size())
	    {
		const Cell &c = r.cells[col_num];

		if (r.isHeading)
		    table += "<TH>" + fmtHTMLCell(c) + "</TH>";
		else
		    table += "<TD>" + fmtHTMLCell(c) + "</TD>";
	    }
	    else
	    {
		// Always want to output a full row of cells otherwise
		// the style is messed up
		if (r.isHeading)
		    table += "<TH></TH>";
		else
		    table += "<TD></TD>";
	    }
	}
	table += "</TR>\n";
    }
    if (current_section.size() > 0)
	table += "</" + current_section + ">\n";

    table += "</TABLE>";

    return table;
}

String Table::renderAsXML()
{
    String table;
    String current_section;

    table = "<TABLE>\n";

    if (caption.size() > 0)
	table += "<CAPTION>" + caption + "</CAPTION>\n";

    size_t num_columns = 0;
    RowVector::const_iterator row_iter;
    for(row_iter = rows.begin(); row_iter != rows.end(); ++row_iter)
    {
	const Row &r = *row_iter;

	if (r.cells.size() > num_columns)
	    num_columns = r.cells.size();
    }

    int row_num;
    for(row_iter = rows.begin(), row_num = 0; row_iter != rows.end(); ++row_iter, row_num++)
    {
	const Row &r = *row_iter;

	String section;
	if (r.isHeading)
	    section = "THEAD";
	else
	    section = "TBODY";
	if (section != current_section)
	{
	    if (current_section.size() > 0)
		table += "</" + current_section + ">\n";

	    current_section = section;
	    table += "<" + current_section + ">\n";
	}

	table += "<TR>";

	for(size_t col_num = 0; col_num < num_columns; col_num++)
	{
	    if (col_num < r.cells.size())
	    {
		const Cell &c = r.cells[col_num];

		if (r.isHeading)
		    table += "<TH>" + fmtHTMLCell(c) + "</TH>";
		else
		    table += "<TD>" + fmtHTMLCell(c) + "</TD>";
	    }
	    else
	    {
		// Always want to output a full row of cells otherwise
		// the style is messed up
		if (r.isHeading)
		    table += "<TH></TH>";
		else
		    table += "<TD></TD>";
	    }
	}
	table += "</TR>\n";
    }
    if (current_section.size() > 0)
	table += "</" + current_section + ">\n";

    table += "</TABLE>";

    return table;
}

String Table::fmtHTMLCell(const Cell &c)
{
    String ret;

    // Break the cell up into lines
    StringVector sv = split_string(c.contents, "\n");
    if (sv.size() > 1)
    {
	StringVector::iterator iter;
	for (iter = sv.begin(); iter != sv.end(); ++iter)
	    ret += (*iter) + "<br/>\n";
    }
    else
	ret = c.contents;

    if (c.colour != COL_DEFAULT)
	ret = setHTMLColour(c.colour, ret);

    return ret;
}
