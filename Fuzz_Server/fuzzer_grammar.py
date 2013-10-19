
from sulley import *
import random


'''
s_initialize("HTTP Requests")
s_group("requests", values=["GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND"])
if s_block_start("test", group="requests"):
    s_delim(" ")
    s_delim("/")
    s_string("index.html")
    s_delim(" ")
    s_string("HTTP")
    s_delim("/")
    s_string("1")
    s_delim(".")
    s_string("1")
    s_static("\r\n\r\n")
s_block_end("test")
'''

'''
SULLEY CHEAT SHEET
===================================================================================================================

s_initialize("your request name here")

s_static("will not mutate this string")     : a static, unmutating value (Aliases: s_raw(), s_dunno(), s_unknown())

s_byte(), s_char()                          : 1 byte
s_word(), s_short()                         : 2 bytes
s_dword(), s_long(), s_int()                : 4 bytes
s_qword(), s_double()                       : 8 bytes

s_string("string here")                     : A string to be mutated

s_binary("0xde")                            : A binary format

s_delim("delimiter here")                   : A delimiter in a protocol (ex: in <test> '<' and '>' are delimiters)


s_block_start("block name", [group="group name", dep="name of dependant primitive", dep_value=value])
s_block_end("block name")

s_group("group name", values=["values", ...])

s_checksum("nametochecksum")
s_repeat("name", min, max)
s_sizer("name"), s_size("name")




===================================================================================================================
SOURCES:
http://www.fuzzing.org/wp-content/SulleyManual.pdf
http://www.exploit-db.com/wp-content/themes/exploit/docs/25717.pdf


'''

#There is a good example of a html lego on pg 11 of : http://www.fuzzing.org/wp-content/SulleyManual.pdf

'''
<html>
<head>
<title></title>
</head>
<body>
<a href="http://127.0.0.1/">anchor text here</a>
<a href="http://127.0.0.1/test">another anchor text here</a>
<a href="http://127.0.0.1/testymctesterson">another another anchor text here</a>
<p>here is some more text to see what happens</p>
</body>
</html>
'''


s_initialize('HTML Total')


if s_block_start("All HTML"):
    s_delim("<")
    s_string("html")
    s_delim(">")

    s_delim("<")
    s_string("head")
    s_delim(">")

    s_delim("<")
    s_string("title")
    s_delim(">")

    s_delim("<")
    s_string("/title")
    s_delim(">")

    s_delim("<")
    s_string("/head")
    s_delim(">")

    # Beginning of Body

    s_delim("<")
    s_string("body")
    s_delim(">")



    # <a href="http://127.0.0.1/">anchor text here</a>
    s_delim("<")
    s_string("a")
    s_delim(" ")
    s_string("href")
    s_delim("=")
    s_delim("\"")
    s_static("http://127.0.0.1")    # try to point it to localhost (make localhost a delim) and then fuzz the other portion of the url?
    s_delim("/")
    s_string("")
    s_delim("\"")
    s_delim(">")
    s_string("anchor text here")
    s_delim("<")
    s_delim("/")
    s_string("a")
    s_delim(">")


    # <a href="http://127.0.0.1/test">another anchor text here</a>
    s_delim("<")
    s_string("a")
    s_delim(" ")
    s_string("href")
    s_delim("=")
    s_delim("\"")
    s_static("http://127.0.0.1")    # try to point it to localhost (make localhost a delim) and then fuzz the other portion of the url?
    s_delim("/")
    s_string("test")
    s_delim("\"")
    s_delim(">")
    s_string("another anchor text here")
    s_delim("<")
    s_delim("/")
    s_string("a")
    s_delim(">")


    # <a href="http://127.0.0.1/testymctesterson">another another anchor text here</a>
    s_delim("<")
    s_string("a")
    s_delim(" ")
    s_string("href")
    s_delim("=")
    s_delim("\"")
    s_static("http://127.0.0.1")    # try to point it to localhost (make localhost a delim) and then fuzz the other portion of the url?
    s_delim("/")
    s_string("testymctesterson")
    s_delim("\"")
    s_delim(">")
    s_string("another another anchor text here")
    s_delim("<")
    s_delim("/")
    s_string("a")
    s_delim(">")

    # <p>here is some more text to see what happens</p>
    s_delim("<")
    s_string("p")
    s_delim(">")
    s_string("here is some more text to see what happens")
    s_delim("<")
    s_string("/p")
    s_delim(">")

s_block_end("All HTML")

s_delim("<")
s_string("a")
s_delim(" ")
s_string("href")
s_delim("=")
s_delim("\"")
s_static("http://127.0.0.1")
s_delim("/")
s_checksum("All HTML")
s_delim("\"")
s_delim(">")
s_string("checksum anchor")
s_delim("<")
s_delim("/")
s_string("a")
s_delim(">")

s_delim("<")
s_string("/body")
s_delim(">")

s_delim("<")
s_string("/html")
s_delim(">")






#---------------------------------------------------------------------------
'''
<html>
<head>
<title></title>
</head>
<body>
<a href="http://127.0.0.1/">test anchor 1</a>
<a href="http://127.0.0.1/test">test anchor 2</a>
<a href="http://127.0.0.1/testymctesterson">test anchor 3</a>
<a href="http://127.0.0.1/<checksum>">extra seed anchor</a>
</body>
</html>
'''

s_initialize("HTML Anchors")

if s_block_start("All HTML"):

    s_static("<html><head><title>Sulley Says Hello!</title></head><body>")

    if s_block_start("anchors"):
        s_static("<a href=\"http://127.0.0.1/")
        s_string("test")
        s_static("\">test anchor 1</a>")

        s_static("<a href=\"http://127.0.0.1")
        s_string("/testymctesterson")
        s_static("\">test anchor 2</a>")

        s_static("<a href=\"http://127.0.0.1/")
        s_string("test")
        s_static("\">test anchor 3</a>")
    s_block_end("anchors")

    s_static("<img src=\"http://127.0.0.1/")
    s_string("myimagestring")
    s_static("\">test image</a>")

    s_static("<a href=\"http://127.0.0.1/")
    s_checksum("anchors", algorithm='sha1')
    s_static("\">internal checksum anchor</a>")

s_block_end("All HTML")

# Extra anchor that will be unique so that the crawler has somewhere to go (if duplicates)
s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm='sha1')
s_static("\">external checksum anchor</a>")

s_static("</body></html>")







