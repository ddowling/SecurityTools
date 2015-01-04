/* $Id$
 *
 * Copyright   : (c) 2015 Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : SecurityTools
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
