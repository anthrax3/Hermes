

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
        s_string("0.623322967477")
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
    # Start of html div lnk_and_img div
    s_static("<div")
    s_static(" class=\"")
    s_string("lnk_and_img")
    s_static("\"")
    s_static(" id=\"")
    s_string("lnk_and_img div")
    s_static("\"")
    s_static(">")
    # Start of html img code
    s_static("<img src=\"http://127.0.0.1/")
    s_string("0.128113768037")
    s_static("\" alt=\"")
    s_string("alt img text")
    s_static("\" />")
    # End of html img code


    s_static("</div>")
    # End of html div lnk_and_img div

    # Start of html div t2_iframe div
    s_static("<div")
    s_static(" class=\"")
    s_string("t2_iframe")
    s_static("\"")
    s_static(" id=\"")
    s_string("t2_iframe div")
    s_static("\"")
    s_static(">")

    s_static("</div>")
    # End of html div t2_iframe div

    # Start of html div t3_object div
    s_static("<div")
    s_static(" class=\"")
    s_string("t3_object")
    s_static("\"")
    s_static(" id=\"")
    s_string("t3_object div")
    s_static("\"")
    s_static(">")

    s_static("</div>")
    # End of html div t3_object div

    # Start of html div t4_js div
    s_static("<div")
    s_static(" class=\"")
    s_string("t4_js")
    s_static("\"")
    s_static(" id=\"")
    s_string("t4_js div")
    s_static("\"")
    s_static(">")

    s_static("</div>")
    # End of html div t4_js div

    # Start of html div t5_applet div
    s_static("<div")
    s_static(" class=\"")
    s_string("t5_applet")
    s_static("\"")
    s_static(" id=\"")
    s_string("t5_applet div")
    s_static("\"")
    s_static(">")

    s_static("</div>")
    # End of html div t5_applet div


s_block_end("All HTML")

s_static("<a href=\"http://127.0.0.1/")
s_checksum("All HTML", algorithm="sha1")
s_static("\">")
s_checksum("All HTML", algorithm="sha1")
s_static("</a>")
s_static("</body></html>")
