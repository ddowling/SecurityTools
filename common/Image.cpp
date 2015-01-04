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
#include "Image.h"
#include "Base64.h"
#include "File.h"

Image::Image()
{
}

void Image::setImage(const String &file_)
{
    file = file_;
}

void Image::setAlternateText(const String &text_)
{
    text = text_;
}

void Image::traverse(ReportVisitor &report_visitor)
{
    report_visitor.visitImage(*this);
}

String Image::renderAsASCII()
{
    return text;
}

String Image::renderAsHTML()
{
    bool include_in_html = true;

    String s = "<IMG SRC=";

    if (include_in_html)
    {
	String s = File::readToString(file);
	String image_type = File::getExtension(file);

	String b64 = Base64::encode(s);

	s += "\"data:image/" + image_type + ";base64," + b64 + "\"";
    }
    else
	s += "\"" + file + "\"";

    if (text.size() != 0)
	s += " ALT=\"" + text + "\"";
    s += ">";

    return s;
}

String Image::renderAsXML()
{
    return renderAsHTML();
}
