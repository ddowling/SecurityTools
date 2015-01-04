/* $Id$
 *
 * Copyright   : (c) 2009 by Witham Laboratories Pty Ltd. All Rights Reserved
 * Project     : PCI SSL Assessment Tool
 * File        : VisitorHTML
 *
 * Author      : Denis Dowling
 * Created     : 8/5/2009
 *
 * Description : Render a report in HTML
 */
#include "VisitorHTML.h"
#include "Section.h"
#include "Paragraph.h"
#include "Table.h"
#include "List.h"
#include "Image.h"

// HTML Cascading Style Sheet
static const char *builtinCSS =
"* {margin: 0; padding: 0;}\n"
"body {font-size: 80%; margin: 10px; padding: 0px; font-family: Verdana, Helvetica, Arial, sans-serif; width: 760px; color: #333333;}\n"
"caption { caption-side : bottom; font-style : italic;}\n"
"h1 {font-size: 250%; margin-top: 10px;}\n"
"h2 {font-size: 200%; margin-top: 25px; margin-bottom: 0px; padding: 5px; background-color: #ECE3FD; border-top: 2px solid #BA9BD4; border-bottom: 1px solid #BA9BD4}\n"
"h3 {font-size: 150%; font-weight: normal; padding: 5px; background-color: #E8EDFD; margin-top: 10px; border-top: 2px solid #8080E4;}\n"
"h5 {font-size: 110%;}\n"
"p {margin-bottom: 15px; text-align: justify; }\n"
"div {margin-bottom: 0px; margin-top: 0px; text-align: justify; }\n"
"table {clear: left; border: solid 1px rgb(150,150,150); empty-cells: show; border-collapse: collapse; background-color: #F5F2FF; width: 100%; text-align: left; margin-bottom: 0px;}\n"
"tr.evenrow {background-color: #EDEBF8;}\n"
"th {background-color: rgb(150,150,150); color: #ffffff; vertical-align: top; padding: 2px;}\n"
"td {vertical-align: top; padding: 2px;}\n"
"ul {margin-left: 20px; margin-top: 0px; margin-bottom: 20px;}\n"
"div.ratings {float:right; width:150px; padding:7px; margin:3px; font-size:14px; font-family:arial,helvetica,sans-serif; color:black; background-color: #FDFFE2; border:1px solid #D5D274; vertical-align:top; }\n"
"font.critical {color: #CD0A3B; text-transform:uppercase; font-weight: bold;}\n"
"font.high {color: #E2A316; text-transform:uppercase; font-weight: bold;}\n"
"font.medium {color: #ECEC04; text-transform:uppercase; font-weight: bold;}\n"
"font.low {color: #9DCA02; text-transform:uppercase; font-weight: bold;}\n"
"font.informational {color: #41A300; text-transform:uppercase; font-weight: bold;}\n"
"font.trivial {color: #CD0A3B; text-transform:uppercase; font-weight: bold;}\n"
"font.easy {color: #E2A316; text-transform:uppercase; font-weight: bold;}\n"
"font.moderate {color: #ECEC04;text-transform:uppercase;  font-weight: bold;}\n"
"font.challenging {color: #9DCA02; text-transform:uppercase; font-weight: bold;}\n"
"font.notapplicable {color: #41A300; text-transform:uppercase; font-weight: bold;}\n"
"font.involved {color: #CD0A3B; text-transform:uppercase; font-weight: bold;}\n"
"font.planned {color: #ECEC04; text-transform:uppercase; font-weight: bold;}\n"
"font.quick {color: #41A300; text-transform:uppercase; font-weight: bold;}\n"
"font.overallrating {font-weight: bold; font-size:15px; padding-bottom: 5px; }\n"
"font.ratings {position: relative; left: 70px;}\n"
"#frontpage {height: 400px; background-color: #F3F3F3; border:1px solid #120E8A;}\n"
"div.companyname {color: #18026B; font-weight: bold; font-size: 250%; text-align: center;}\n"
"div.reporttitle {color: #2A2A2F; font-weight: bold; font-size: 200%; text-align: center; margin-top: 100px;}\n"
"div.reportdate {color: #2A2A2F; font-size: 150%; text-align: center; text-transform: uppercase}\n"
"#contents {margin-left: 50px;}\n"
"#tableindex {margin-left: 50px;}\n"
"pre.code {background-color: #F3F3F3; padding-top: 5px; padding-bottom: 5px; margin-top: 5px; margin-bottom: 15px; font-weight: bold;font-family: courier; font-size: 100%}\n"
".cmduser {font-style: italic; font-weight: normal}\n";

VisitorHTML::VisitorHTML()
    : sectionLevel(0)
{
}

String VisitorHTML::getHTML() const
{
    return ss.str();
}

void VisitorHTML::enterReport(Report &r)
{
    ss << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n";
    ss << "<html>\n";
    ss << "<head>\n";

    String title = r.getTitle();
    if (title.size() > 0)
	ss << "<title>" + title + "</title>\n";

    ss << "<meta name=\"description\" content=\"%s\">\n";
    String author = r.getAuthor();
    if (author.size() > 0)
	ss << "<meta name=\"author\" content=\"" + author + "\">\n";
    ss << "<meta http-equiv=\"Content-Style-Type\" content=\"text/css\">\n";


    ss <<  "<style type='text/css'>\n"
       << "<!--\n"
       << builtinCSS
       << "--></style>\n"
       << "</head>\n"
       << "<body id=\"report\">\n";
}

void VisitorHTML::exitReport(Report &r)
{
    ss << "</body>\n"
       << "</html>\n";
}

void VisitorHTML::enterSection(Section &s)
{
    sectionLevel++;

    ss << "<h" << sectionLevel << ">" << s.getHeading()
       << "</h" << sectionLevel << ">\n";
}

void VisitorHTML::exitSection(Section &s)
{
    sectionLevel--;
}

void VisitorHTML::enterParagraph(Paragraph &p)
{
    ss << "<p>" << p.getText() << "</p>\n";
}

void VisitorHTML::exitParagraph(Paragraph &p)
{
    // Nothing to do
}

void VisitorHTML::enterTable(Table &t)
{
    ss << t.renderAsHTML();
}

void VisitorHTML::exitTable(Table &t)
{
    // Nothing to do
}

void VisitorHTML::enterList(List &l)
{
    ss << l.renderAsHTML();
}

void VisitorHTML::exitList(List &l)
{
    // Nothing to do
}

void VisitorHTML::visitImage(Image &i)
{
    ss << i.renderAsHTML();
}
