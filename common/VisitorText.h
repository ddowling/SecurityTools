/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
 * File        : VisitorText
 *
 * Author      : Denis Dowling
 * Created     : 8/5/2009
 *
 * Description : Render a report in Text
 */
#ifndef VISITOR_TEXT_H
#define VISITOR_TEXT_H

#include "Report.h"

class VisitorText : public ReportVisitor
{
 public:
    VisitorText(bool use_colour = false);

    String getText() const;

 protected:
    int sectionLevel;
    StringStream ss;
    bool useColour;

    virtual void enterReport(Report &r);
    virtual void exitReport(Report &r);

    virtual void enterSection(Section &s);
    virtual void exitSection(Section &s);

    virtual void enterParagraph(Paragraph &p);
    virtual void exitParagraph(Paragraph &p);

    virtual void enterTable(Table &t);
    virtual void exitTable(Table &t);

    virtual void enterList(List &t);
    virtual void exitList(List &t);

    virtual void visitImage(Image &i);
};

#endif
