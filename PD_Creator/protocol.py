

# Auto Generated Protocol Definition
# SulleyHelpers.py


from sulley import *
import random

s_initialize("Protocol Definition")

if s_block_start("All HTML"):
    s_static("<html><head><title>Sulley Says Hello!</title></head><body>")
    if s_block_start("t1_block"):
        # Start of html img code
        s_static("<img src=\"http://127.0.0.1/")
        s_string("0.767727035554")
        s_static("\" alt=\"")
        s_string("alt img text")
        s_static("\" />")
        # End of html img code


    s_block_end("t1_block")

    s_static("<a href=\"http://127.0.0.1/")
    s_checksum("t1_block", algorithm="sha1")
    s_static("\">")
    s_checksum("t1_block", algorithm="sha1")
    s_static("</a>")
    # Start of html iFrame test 2
    s_static("<iframe")
    s_static(" name=\"")
    s_string("test 2")
    s_static("\"")
    s_static(" src=\"")
    s_string("test 2 source")
    s_static("\"")
    s_static(" onload=\"")
    s_string("test")
    s_static("\"")
    s_static(">")
    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.178149245047")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code


    s_static("</iframe>")
    # End of html iFrame test 2

    # Start of JavaScript code
    s_static("<script")
    s_static(" src=\"")
    s_string("test")
    s_static("\"")
    s_static(">")
    s_static("document.getElementById(\"")
    s_string("0.555293620041")
    s_static("\").innerHTML=\"")
    s_string("0.938426814395")
    s_static("\"")
    s_static("</script>")

    s_static("document.location=\"")
    s_string("127.0.0.1")
    s_static("\"")
    # End of JavaScript code

    s_static("<applet code=\"")
    s_string("0.162287633382")
    s_static("\">")
    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.178149245047")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code

    s_static("</applet>")

s_block_end("All HTML")

s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm="sha1")
s_static("\">")
s_checksum("All HTML", algorithm="sha1")
s_static("</a>")
s_static("</body></html>")
if s_block_start("All HTML"):
    s_static("<html><head><title>Sulley Says Hello!</title></head><body>")
    if s_block_start("t1_block"):
        # Start of html anchor code
        s_static("<a href=\"http://127.0.0.1/")
        s_string("0.0539755969416")
        s_static("\">test 1</a>")
        # End of html anchor code

        # Start of html img code
        s_static("<img src=\"http://127.0.0.1/")
        s_string("0.27582553206")
        s_static("\" alt=\"")
        s_string("alt img text")
        s_static("\" />")
        # End of html img code


    s_block_end("t1_block")

    s_static("<a href=\"http://127.0.0.1/")
    s_checksum("t1_block", algorithm="sha1")
    s_static("\">")
    s_checksum("t1_block", algorithm="sha1")
    s_static("</a>")
    # Start of html iFrame test 2
    s_static("<iframe")
    s_static(" name=\"")
    s_string("test 2")
    s_static("\"")
    s_static(" src=\"")
    s_string("test 2 source")
    s_static("\"")
    s_static(" onload=\"")
    s_string("test")
    s_static("\"")
    s_static(">")
    # Start of html anchor code
    s_static("<a href=\"http://127.0.0.1/")
    s_string("0.122425054586")
    s_static("\">test 1</a>")
    # End of html anchor code

    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.484633536154")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code


    s_static("</iframe>")
    # End of html iFrame test 2

    # Start of html object code
    s_static("<object")
    s_static(" data=\"")
    s_string("test")
    s_static("\"")
    s_static(" name=\"")
    s_string("test object")
    s_static("\"")
    s_static(">")
    # Start of html anchor code
    s_static("<a href=\"http://127.0.0.1/")
    s_string("0.122425054586")
    s_static("\">test 1</a>")
    # End of html anchor code

    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.484633536154")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code


    s_static("</object>")
    # End of html object code

    s_static("<applet code=\"")
    s_string("0.876526488307")
    s_static("\">")
    # Start of html anchor code
    s_static("<a href=\"http://127.0.0.1/")
    s_string("0.122425054586")
    s_static("\">test 1</a>")
    # End of html anchor code

    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.484633536154")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code

    s_static("</applet>")

s_block_end("All HTML")

s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm="sha1")
s_static("\">")
s_checksum("All HTML", algorithm="sha1")
s_static("</a>")
s_static("</body></html>")
