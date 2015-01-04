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
#ifndef SECTION_H
#define SECTION_H

#include "Report.h"

class Section : public ReportElement
{
 public:
    Section();

    // The section heading
    void setHeading(const String &h);
    String getHeading() const;

    Paragraph &addParagraph();

    virtual void traverse(ReportVisitor &report_visitor);

 protected:
    String heading;
};

#endif
