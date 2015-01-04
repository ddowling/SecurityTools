/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : report_test.cpp
 *
 * Author      : Denis Dowling
 * Created     : 7/12/2009
 *
 * Description : Test for the Report generation class
 */
#include "Report.h"
#include "Section.h"
#include "Paragraph.h"
#include "Table.h"
#include "List.h"

#include "VisitorHTML.h"
#include "VisitorText.h"
#include "BoxDrawingCharacters.h"

#include "iostream"
using namespace std;

int main(int argc, char **argv)
{
    if (argc > 1)
    {
	if (!setCodePageFromString(argv[1]))
	{
	    cerr << "Cannot set code page to " << argv[1] << endl;
	    return 1;
	}
    }

    Report report;

    report.setTitle("Test Report");
    report.setAuthor("Denis Dowling");

    Section &s = report.addSection();
    s.setHeading("Introduction");

    Paragraph &p = s.addParagraph();
    p.setText("This report acts as a test of the Report class. It should exercise all of the features of this class.");

    p = s.addParagraph();
    p.setText("The following table contains information about nothing in particular");

    Table &t = p.addTable();
    t.addHeadingRow();
    t.addCell("Column1");
    t.addCell("Column2");
    t.addCell("Column3");
    for (int r = 0; r < 10; r++)
    {
	t.addRow();
	for (int c = 0; c < 3; c++)
	{
	    StringStream ss;
	    ss << "data " << r << c;
	    t.addCell(ss.str());
	}
    }

    List &l = p.addList();
    l.setOrderedList(true);
    l.addItem("First item");
    l.addItem("Second item");
    l.addItem("Third item");
    l.addItem("Forth item");

    if (0)
    {
	VisitorHTML v;
	report.traverse(v);
	cout << v.getHTML();
    }
    else
    {
	VisitorText v;
	report.traverse(v);
	cout << v.getText();
    }
}
