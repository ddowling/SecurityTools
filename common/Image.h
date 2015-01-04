/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : Image
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : A Image that can be rendered into a number of different formats
 */
#ifndef IMAGE_H
#define IMAGE_H

#include "Report.h"

class Image : public ReportElement
{
 public:
    Image();

    void setImage(const String &file);

    void setAlternateText(const String &text);

    virtual void traverse(ReportVisitor &report_visitor);

    String renderAsASCII();
    String renderAsHTML();
    String renderAsXML();

 protected:
    String file;
    String text;
};

#endif
