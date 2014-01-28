'''

    Author: HTMLTreeConstructor

    Description:
        Auto Generated Protocol Definition: Chromosome: [1, 0, 0, 0, 1, 0, 0]
    Source: PDHelpers.py


    Created: 2014-01-27 20:09:20.421000
'''


from sulley import *
import random

s_initialize("Protocol Definition")

s_static("<html>")
s_static("<head>")
s_static("<title>")
s_string("Sulley Says Hello!")
s_static("</title>")
s_static("</head>")
s_static("<body>")

# Beginning of block: body_block
if s_block_start("body_block"):
    s_string("body_block+assurance")

    # Beginning of block: body_block_a1_block
    if s_block_start("body_block_a1_block"):
        s_string("body_block_a1_block+assurance")

        # Begin <a> tag

        s_static("<a ")
        s_static("alt=\"")
        s_string("body_block_a1")
        s_static("\" ")
        s_static("href=\"127.0.0.1/")
        s_string("body_block_a1")
        s_static("\" ")
        s_static(">")
        s_static("</a>")
        # End <a> tag

    s_block_end("body_block_a1_block")


    # Begin <a> tag

    s_static("<a ")
    s_static("alt=\"")
    s_string("body_block_a1_block")
    s_static("\" ")
    s_static("href=\"")
    s_checksum("body_block_a1_block", algorithm="sha1")
    s_static("\" ")
    s_static(">")
    s_static("</a>")
    # End <a> tag


    # Begin <object> tag

    s_static("<object>")

    # Begin <a> tag

    s_static("<a ")
    s_static("alt=\"")
    s_string("body_block_obj1_a1")
    s_static("\" ")
    s_static("href=\"127.0.0.1/")
    s_string("body_block_obj1_a1")
    s_static("\" ")
    s_static(">")
    s_static("</a>")
    # End <a> tag

    s_static("</object>")
    # End <object> tag

s_block_end("body_block")


# Begin <a> tag

s_static("<a ")
s_static("alt=\"")
s_string("body_block")
s_static("\" ")
s_static("href=\"")
s_checksum("body_block", algorithm="sha1")
s_static("\" ")
s_static(">")
s_static("</a>")
# End <a> tag

s_static("</body>")
s_static("</html>")
