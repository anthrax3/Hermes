'''

    Author: HTMLTreeConstructor

    Description:
        Auto Generated Protocol Definition
        Source: PDHelpers.py

'''


from sulley import *
import random

s_initialize("Protocol Definition")

s_static("<html>")
s_static("<head>")
s_static("<title>")
s_string("Sulley Says Hello!")
s_static("</title>")

# Begin <script> tag

s_static("<script ")
s_static("language=\"")
s_string("JavaScript")
s_static("\" ")
s_static(">")

# JavaScript Code

s_static("document.getElementById(\"")
s_string("test")
s_static("\").innerHTML=\"")
s_string("test")
s_static("\"")
s_static("</script>")
# End <script> tag

s_static("</head>")
s_static("<body>")

# Beginning of block: body_block
if s_block_start("body_block"):
    s_string("body_block+assurance")

    # Beginning of block: body_block_a1_block
    if s_block_start("body_block_a1_block"):
        s_string("body_block_a1_block+assurance")
    s_block_end("body_block_a1_block")


    # Begin <iframe> tag

    s_static("<iframe ")
    s_static("src=\"127.0.0.1/")
    s_string("testpath")
    s_static("\" ")
    s_static(">")
    s_static("</iframe>")
    # End <iframe> tag


    # Begin <object> tag

    s_static("<object>")

    # Begin <img> tag

    s_static("<img ")
    s_static("src=\"127.0.0.1/")
    s_string("somepath")
    s_static("\" ")
    s_static(">")
    s_static("</img>")
    # End <img> tag

    s_static("</object>")
    # End <object> tag


    # Begin <applet> tag

    s_static("<applet ")
    s_static("code=\"127.0.0.1/")
    s_string("sulleylikesapples")
    s_static("\" ")
    s_static(">")

    # Begin <img> tag

    s_static("<img ")
    s_static("src=\"127.0.0.1/")
    s_string("somepath")
    s_static("\" ")
    s_static(">")
    s_static("</img>")
    # End <img> tag

    s_static("</applet>")
    # End <applet> tag

s_block_end("body_block")

s_static("</body>")
s_static("</html>")
