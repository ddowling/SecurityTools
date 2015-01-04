/* $Id$
 *
 * Copyright   : (c) 2009 by Open Source Solutions Pty Ltd. All Rights Reserved
 * Project     : Forensic Tools
 * File        : List
 *
 * Author      : Denis Dowling
 * Created     : 14/12/2009
 *
 * Description : A List that can be rendered into a number of different formats
 */
#include "List.h"

List::List()
    : orderedList(false), definitionList(false)
{
}

void List::setOrderedList(bool b)
{
    orderedList = b;
}

bool List::getOrderedList()
{
    return orderedList;
}

void List::setDefinitionList(bool b)
{
    definitionList = b;
}

bool List::getDefinitionList()
{
    return definitionList;
}

// Add an item to the list
void List::addItem(String text)
{
    ListItem li;
    li.text = text;

    listItems.push_back(li);
}

void List::addItem(String definition, String text)
{
    ListItem li;
    li.definition = definition;
    li.text = text;

    listItems.push_back(li);
}

void List::traverse(ReportVisitor &report_visitor)
{
    report_visitor.enterList(*this);

    ReportElement::traverse(report_visitor);

    report_visitor.exitList(*this);
}

String List::renderAsASCII()
{
    StringStream ss;
    ListItemVector::iterator iter;
    int n = 0;

    // FIXME wordwrap and indent in this function

    for(iter = listItems.begin(); iter != listItems.end(); ++iter)
    {
	ListItem &li = *iter;
	if (orderedList)
	{
	    n++;
	    ss << n << ". " << li.text << "\n";
	}
	else if (definitionList)
	{
	    ss << "  " << li.definition << "\n";
	    ss << "    " << li.text << "\n";
	}
	else
	    ss << "- " << li.text << "\n";
    }

    return ss.str();
}

String List::renderAsHTML()
{
    String lt;
    if (orderedList)
	lt = "OL";
    else if (definitionList)
	lt = "DL";
    else
	lt = "UL";

    StringStream ss;

    ss << "<" << lt << ">\n";

    ListItemVector::iterator iter;

    for(iter = listItems.begin(); iter != listItems.end(); ++iter)
    {
	ListItem &li = *iter;
	if (definitionList)
	{
	    ss << "<DT>" << li.text << "</DT>\n";
	}
	else
	    ss << "<DD>" << li.text << "</DD>\n";
    }

    ss << "</" << lt << ">\n";

    return ss.str();
}

String List::renderAsXML()
{
    return renderAsHTML();
}
