/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
 * File        : VisitorText
 *
 * Author      : Denis Dowling
 * Created     : 8/5/2009
 *
 * Description : Render a report in Text
 */
#include "VisitorText.h"
#include "Section.h"
#include "Paragraph.h"
#include "Table.h"
#include "WordWrap.h"
#include "BoxDrawingCharacters.h"
#include "List.h"
#include "Image.h"

VisitorText::VisitorText(bool use_colour)
    : sectionLevel(0), useColour(use_colour)
{
}

String VisitorText::getText() const
{
    return ss.str();
}

void VisitorText::enterReport(Report &r)
{
}

void VisitorText::exitReport(Report &r)
{
}

void VisitorText::enterSection(Section &s)
{
    sectionLevel++;

    ss << s.getHeading() << "\n";
    String rule = getLineStr(B_DOUBLE_HORIZONTAL,
			     s.getHeading().size());
    ss << rule << "\n\n";
}

void VisitorText::exitSection(Section &s)
{
    sectionLevel--;
}

void VisitorText::enterParagraph(Paragraph &p)
{
    // FIXME Where does the width come from
    StringVector sv = wordWrap(p.getText(), 80);
    StringVector::iterator iter;
    for(iter = sv.begin(); iter != sv.end(); ++iter)
	ss << (*iter) << "\n";
}

void VisitorText::exitParagraph(Paragraph &p)
{
    ss << "\n";
}

void VisitorText::enterTable(Table &t)
{
    ss << t.renderAsASCII(useColour);
}

void VisitorText::exitTable(Table &t)
{
    // Nothing to do
}

void VisitorText::enterList(List &l)
{
    ss << l.renderAsASCII();
}

void VisitorText::exitList(List &l)
{
    // Nothing to do
}

void VisitorText::visitImage(Image &i)
{
    ss << i.renderAsASCII();
}
