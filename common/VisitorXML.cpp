/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
 * File        : VisitorXML
 *
 * Author      : Denis Dowling
 * Created     : 13/12/2009
 *
 * Description : Render a report in XML. This output can then be converted
 *               to other formats using XSL
 */
#include "VisitorXML.h"
#include "Section.h"
#include "Paragraph.h"
#include "Table.h"
#include "List.h"
#include "Image.h"

VisitorXML::VisitorXML()
{
}

String VisitorXML::getXML() const
{
    return ss.str();
}

void VisitorXML::enterReport(Report &r)
{
    ss << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";

    ss << "<report>\n";

    String title = r.getTitle();
    if (title.size() > 0)
	ss << "<title>" + title + "</title>\n";

    String author = r.getAuthor();
    if (author.size() > 0)
	ss << "<author" + author + "</author>\n";
}

void VisitorXML::exitReport(Report &r)
{
    ss << "</report>\n";
}

void VisitorXML::enterSection(Section &s)
{
    ss << "<section>\n";
    ss << "<heading>" << s.getHeading() << "</heading>\n";
}

void VisitorXML::exitSection(Section &s)
{
    ss << "</section>\n";
}

void VisitorXML::enterParagraph(Paragraph &p)
{
    ss << "<para>" << p.getText() << "</para>\n";
}

void VisitorXML::exitParagraph(Paragraph &p)
{
    // Nothing to do
}

void VisitorXML::enterTable(Table &t)
{
    ss << t.renderAsXML();
}

void VisitorXML::exitTable(Table &t)
{
    // Nothing to do
}

void VisitorXML::enterList(List &l)
{
    ss << l.renderAsXML();
}

void VisitorXML::exitList(List &l)
{
    // Nothing to do
}

void VisitorXML::visitImage(Image &i)
{
    ss << i.renderAsXML();
}
