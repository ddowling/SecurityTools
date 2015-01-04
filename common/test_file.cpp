#include "File.h"
#include <iostream>

using namespace std;

int main()
{
    String filename = "test_file.cpp";

    cout << "Filename " << filename << endl;
    cout << "Extension " << File::getExtension(filename) << endl;

    String contents = File::readToString(filename);

    cout << "Contents :" << endl;
    cout << contents << endl;
}
