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
#ifndef REPORT_H
#define REPORT_H

#include "String.h"
#include "ref_ptr.h"
#include <vector>

// Forward declarations for the visitor
class Report;
class Section;
class Paragraph;
class Table;
class List;
class Image;

// Visitor pattern for the Report class. It will be called when we traverse
// the Report composite pattern
class ReportVisitor
{
 public:
    virtual ~ReportVisitor();

    // FIXME only non-leaf nodes need and enter and exit. Need to determine what elements need to support children
    virtual void enterReport(Report &r) = 0;
    virtual void exitReport(Report &r) = 0;

    virtual void enterSection(Section &s) = 0;
    virtual void exitSection(Section &s) = 0;

    virtual void enterParagraph(Paragraph &p) = 0;
    virtual void exitParagraph(Paragraph &p) = 0;

    virtual void enterTable(Table &t) = 0;
    virtual void exitTable(Table &t) = 0;

    virtual void enterList(List &t) = 0;
    virtual void exitList(List &t) = 0;

    virtual void visitImage(Image &i) = 0;
};

// Base class for elements of a report
class ReportElement
{
 public:
    virtual ~ReportElement();

    virtual void traverse(ReportVisitor &report_visitor) = 0;

 protected:
    ReportElement();

    // naked pointer to the parent as we want this to be a
    // weak reference
    ReportElement *parent;

    typedef ref_ptr<ReportElement> ReportElementPtr;
    typedef std::vector<ReportElementPtr> ReportElementVector;
    ReportElementVector children;

    void appendChild(ReportElementPtr child);
};

class Report : public ReportElement
{
 public:
    Report();

    // The title of the report
    void setTitle(String title);
    String getTitle() const;

    // The author of the report
    void setAuthor(String author);
    String getAuthor() const;

    Section &addSection();

    virtual void traverse(ReportVisitor &report_visitor);

 protected:
    String title;
    String author;
};

#endif
