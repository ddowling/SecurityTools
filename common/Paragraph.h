/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
 * File        : Paragraph
 *
 * Author      : Denis Dowling
 * Created     : 7/12/2009
 *
 * Description : class to implement a report Paragraph
 */
#ifndef PARAGRAPH_H
#define PARAGRAPH_H

#include "Report.h"

class Paragraph : public ReportElement
{
 public:
    Paragraph();

    // The paragraph text
    void setText(const String &h);
    String getText() const;

    Table &addTable();
    List &addList();
    Image &addImage();

    virtual void traverse(ReportVisitor &report_visitor);

 protected:
    String text;
};

#endif
