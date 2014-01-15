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
s_static("</head>")
s_static("<body>")

# Beginning of block: body_block
if s_block_start("body_block"):
    s_string("body_block+assurance")

    # Beginning of block: body_block_a1_block
    if s_block_start("body_block_a1_block"):
        s_string("body_block_a1_block+assurance")
    s_block_end("body_block_a1_block")


    # Begin <object> tag

    s_static("<object>")
    s_static("</object>")
    # End <object> tag


    # Beginning of block: 0.691682228212
    if s_block_start("0.691682228212"):
        s_string("0.691682228212+assurance")

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


        # Begin <object> tag

        s_static("<object>")
        s_static("</object>")
        # End <object> tag


        # Beginning of block: 0.240156320417
        if s_block_start("0.240156320417"):
            s_string("0.240156320417+assurance")

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


            # Begin <object> tag

            s_static("<object>")
            s_static("</object>")
            # End <object> tag


            # Beginning of block: 0.387564652202
            if s_block_start("0.387564652202"):
                s_string("0.387564652202+assurance")

                # Begin <div> tag

                s_static("<div ")
                s_static("id=\"")
                s_string("body_block_div_div_div")
                s_static("\" ")
                s_static(">")
                s_static("</div>")
                # End <div> tag

            s_block_end("0.387564652202")

            s_static("</div>")
            # End <div> tag

        s_block_end("0.240156320417")

        s_static("</div>")
        # End <div> tag

    s_block_end("0.691682228212")

s_block_end("body_block")

s_static("</body>")
s_static("</html>")
