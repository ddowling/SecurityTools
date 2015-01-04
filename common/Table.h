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
#ifndef TABLE_H
#define TABLE_H

#include <vector>
#include "Report.h"
#include "Colour.h"

class Table : public ReportElement
{
 public:
    Table();

    // Add a caption to the table
    void addCaption(String caption);

    // Add a heading row to a table
    void addHeadingRow();

    // Add a new row to a table
    void addRow();

    void addCell(String contents);

    void setCellColour(Colour c);

    virtual void traverse(ReportVisitor &report_visitor);

    String renderAsASCII(bool use_colour);
    String renderAsHTML();
    String renderAsXML();

 protected:
    String caption;
    String tableClass;

    struct Cell
    {
	String contents;
	Colour colour;
	StringVector wrappedContents;
    };
    typedef std::vector<Cell> CellVector;

    struct Row
    {
	bool isHeading;
	CellVector cells;
	int height;
    };
    typedef std::vector<Row> RowVector;

    RowVector rows;

    typedef std::vector<int> IntVector;
    IntVector colWidths;

    String addHRule(const Row &r, bool top, bool bottom);
    void determineColumnWidths();
    void determineRowHeights();
    void wrapCells();

    String fmtHTMLCell(const Cell &c);
};

#endif
