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
#ifndef LIST_H
#define LIST_H

#include <vector>
#include "Report.h"

class List : public ReportElement
{
 public:
    List();

    void setOrderedList(bool b);
    bool getOrderedList();

    void setDefinitionList(bool b);
    bool getDefinitionList();

    // Add an item to the list
    void addItem(String text);

    void addItem(String definition, String text);

    virtual void traverse(ReportVisitor &report_visitor);

    String renderAsASCII();
    String renderAsHTML();
    String renderAsXML();

 protected:
    bool orderedList;
    bool definitionList;

    struct ListItem
    {
	String definition;
	String text;
    };
    typedef std::vector<ListItem> ListItemVector;

    ListItemVector listItems;
};

#endif
