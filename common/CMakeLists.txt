# Common library files

#set(CMAKE_CXX_FLAGS "-g -Wall")

add_library(common STATIC
    Report.cpp
    Section.cpp
    Paragraph.cpp
    Table.cpp
    List.cpp
    Image.cpp
    ref_ptr.cpp
    VisitorHTML.cpp
    VisitorText.cpp
    VisitorXML.cpp
    String.cpp
    TextProperty.cpp
    WordWrap.cpp
    BoxDrawingCharacters.cpp
    Colour.cpp
    File.cpp
    Base64.cpp
)

# Test programs
add_executable(report_test report_test.cpp)
target_link_libraries(report_test common)

add_executable(test_line_draw test_line_draw.cpp)

add_executable(test_wordwrap test_wordwrap.cpp WordWrap.cpp String.cpp)

add_executable(test_file test_file.cpp File.cpp String.cpp)
