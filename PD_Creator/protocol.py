

# Auto Generated Protocol Definition
# SulleyHelpers.py


from sulley import *
import random

s_initialize("Protocol Definition")

if s_block_start("All HTML"):
    s_static("<html><head><title>Sulley Says Hello!</title></head><body>")
    if s_block_start("anchors"):
        s_static("<a href=\"http://127.0.0.1/")
        s_string("0.44340301383")
        s_static("\">test 1</a>")

        s_static("<a href=\"http://127.0.0.1/")
        s_string("0.99825053562")
        s_static("\">test 2</a>")

        s_static("<a href=\"http://127.0.0.1/")
        s_string("0.405280556563")
        s_static("\">test 4</a>")


    s_block_end("anchors")
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.142858102278")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    s_static("<a href=\"http://127.0.0.1/")
    s_checksum("anchors", algorithm="sha1")
    s_static("\">internal checksum anchor</a>")

s_block_end("All HTML")
s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm="sha1")
s_static("\">external checksum anchor</a>")
s_static("</body></html>")
