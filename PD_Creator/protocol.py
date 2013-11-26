

# Auto Generated Protocol Definition
# SulleyHelpers.py


from sulley import *
import random

s_initialize("Protocol Definition")

if s_block_start("All HTML"):
    s_static("<html><head><title>Sulley Says Hello!</title></head><body>")
    if s_block_start("t1_block"):
        # Start of html anchor code
        s_static("<a href=\"http://127.0.0.1/")
        s_string("0.501348634673")
        s_static("\">test 1</a>")
        # End of html anchor code


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
    s_string("0.381066116326")
    s_static("\">test 1</a>")
    # End of html anchor code


    s_static("</iframe>")
    # End of html iFrame test 2

    s_static("<applet code=\"")
    s_string("0.939222960705")
    s_static("\">")
    # Start of html anchor code
    s_static("<a href=\"http://127.0.0.1/")
    s_string("0.381066116326")
    s_static("\">test 1</a>")
    # End of html anchor code

    s_static("</applet>")

s_block_end("All HTML")

s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm="sha1")
s_static("\">")
s_checksum("All HTML", algorithm="sha1")
s_static("</a>")
s_static("</body></html>")
