#include <vector>
#include <iostream>
#include "WordWrap.h"

using namespace std;

void show(const char *label, StringVector &sv)
{
    cout << label << " lines=" << lines(sv) << " columns=" << columns(sv)
	 << " :" << endl;
    for(size_t i = 0; i < sv.size(); i++)
	cout << "'" <<  sv[i] << "'" << endl;
}

int main()
{
    const char *s0 = "Short line with no wrap";
    StringVector sv = wordWrap(s0, 80);
    show("Word wrapped 80", sv);

    const char *s1 =
	"This is line1\n"
	"This is line2\n"
	"This is line3";

    sv = split_string(s1, "\n");

    show("Lines", sv);

    sv = split_string(s1, " \t\n");
    show("Words", sv);

    sv = wordWrap(s1, 20);
    show("Word wrapped 20", sv);

    sv = wordWrap(s1, 10);
    show("Word wrapped 10", sv);

    sv = wordWrap(s1, 5);
    show("Word wrapped 5", sv);

    sv = wordWrap(s1, 3);
    show("Word wrapped 3", sv);

    const char *s2 =
	"Henry Dorsett Case is a low-level hustler in the dystopian "
	"underworld of Chiba City, Japan. Once a talented computer hacker, "
	"Case was caught stealing from his employer. As punishment for his "
	"theft, Case's central nervous system was damaged with a mycotoxin, "
	"leaving him unable to use his brain-computer interface to access the "
	"global computer network in cyberspace.";

    sv = wordWrap(s2, 60);
    show("Word wrap 60", sv);

    sv = wordWrapOptimum(s2, 60);
    show("Word wrap Optimum 60", sv);
}
