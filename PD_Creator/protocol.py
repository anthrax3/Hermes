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


    # Beginning of block: 0.548487546764
    if s_block_start("0.548487546764"):
        s_string("0.548487546764+assurance")

        # Begin <div> tag

        s_static("<div ")
        s_static("id=\"")
        s_string("body_block_div")
        s_static("\" ")
        s_static(">")

        # Beginning of block: body_block_div_a1_block
        if s_block_start("body_block_div_a1_block"):
            s_string("body_block_div_a1_block+assurance")
        s_block_end("body_block_div_a1_block")


        # Begin <iframe> tag

        s_static("<iframe ")
        s_static("src=\"127.0.0.1/")
        s_string("testpath")
        s_static("\" ")
        s_static(">")
        s_static("</iframe>")
        # End <iframe> tag


        # Beginning of block: 0.276126337338
        if s_block_start("0.276126337338"):
            s_string("0.276126337338+assurance")

            # Begin <div> tag

            s_static("<div ")
            s_static("id=\"")
            s_string("body_block_div_div")
            s_static("\" ")
            s_static(">")

            # Beginning of block: body_block_div_div_a1_block
            if s_block_start("body_block_div_div_a1_block"):
                s_string("body_block_div_div_a1_block+assurance")
            s_block_end("body_block_div_div_a1_block")


            # Begin <iframe> tag

            s_static("<iframe ")
            s_static("src=\"127.0.0.1/")
            s_string("testpath")
            s_static("\" ")
            s_static(">")
            s_static("</iframe>")
            # End <iframe> tag


            # Beginning of block: 0.334247908623
            if s_block_start("0.334247908623"):
                s_string("0.334247908623+assurance")

                # Begin <div> tag

                s_static("<div ")
                s_static("id=\"")
                s_string("body_block_div_div_div")
                s_static("\" ")
                s_static(">")
                s_static("</div>")
                # End <div> tag

            s_block_end("0.334247908623")

            s_static("</div>")
            # End <div> tag

        s_block_end("0.276126337338")

        s_static("</div>")
        # End <div> tag

    s_block_end("0.548487546764")

s_block_end("body_block")

s_static("</body>")
s_static("</html>")
