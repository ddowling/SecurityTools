/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
 * File        : Section
 *
 * Author      : Denis Dowling
 * Created     : 7/12/2009
 *
 * Description : class to implement a report Section
 */
#include "Section.h"
#include "Paragraph.h"

Section::Section()
{
}

// The section heading
void Section::setHeading(const String &h)
{
    heading = h;
}

String Section::getHeading() const
{
    return heading;
}

Paragraph & Section::addParagraph()
{
    Paragraph *p = new Paragraph;

    ReportElement::ReportElementPtr pp(p);
    appendChild(pp);

    return *p;
}


void Section::traverse(ReportVisitor &report_visitor)
{
    report_visitor.enterSection(*this);

    ReportElement::traverse(report_visitor);

    report_visitor.exitSection(*this);
}
