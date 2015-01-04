/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
 * File        : Report
 *
 * Author      : Denis Dowling
 * Created     : 8 May 2009
 *
 * Description : classes to implement the Report Composite pattern
 */
#include "Report.h"
#include "Section.h"
#include "Assert.h"

// ********
// Visitor pattern for the Report class. It will be called when we traverse
// the Report composite pattern
ReportVisitor::~ReportVisitor()
{
}

void ReportVisitor::enterReport(Report &r)
{
}

void ReportVisitor::exitReport(Report &r)
{
}

void ReportVisitor::enterSection(Section &s)
{
}

void ReportVisitor::exitSection(Section &s)
{
}

void ReportVisitor::enterParagraph(Paragraph &p)
{
}

void ReportVisitor::exitParagraph(Paragraph &p)
{
}

void ReportVisitor::enterTable(Table &t)
{
}

void ReportVisitor::exitTable(Table &t)
{
}

// ********
// Base class for elements of a report
ReportElement::ReportElement()
    : parent(0)
{
}

ReportElement::~ReportElement()
{
}

void ReportElement::appendChild(ReportElementPtr child)
{
    ASSERT(child->parent == 0);

    child->parent = this;
    children.push_back(child);
}

void ReportElement::traverse(ReportVisitor &report_visitor)
{
    ReportElementVector::iterator iter;

    for(iter = children.begin(); iter != children.end(); ++iter)
    {
	ReportElementPtr p = *iter;

	p->traverse(report_visitor);
    }
}


// ********
Report::Report()
{
}

// The title of the report
void Report::setTitle(String title_)
{
    title = title_;
}

String Report::getTitle() const
{
    return title;
}

// The author of the report
void Report::setAuthor(String author_)
{
    author = author_;
}

String Report::getAuthor() const
{
    return author;
}

Section & Report::addSection()
{
    Section *s = new Section;

    ReportElement::ReportElementPtr sp(s);
    appendChild(sp);

    return *s;
}

void Report::traverse(ReportVisitor &report_visitor)
{
    report_visitor.enterReport(*this);

    ReportElement::traverse(report_visitor);

    report_visitor.exitReport(*this);
}

