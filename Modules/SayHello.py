"""
    SayHello.py
    Purpose: Simple module to show users different ASCII art when the script is started.
    Author: Jackson Nestler
"""
# General imports
import random
# Module imports

# Telling Pylint to ignore the "errors" in ASCII art:
# pylint: disable=anomalous-backslash-in-string
def greetUser():
    titleChoice = random.randint(1, 8)
    if titleChoice == 1:
        print('''
        .-.
        (o o) boo!
        | O \\
        \   \\
        `~~~'

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Art by Donovan Bake

                ''')
    if titleChoice == 2:
        print('''

                      .-.
         heehee      /aa \_
                   __\-  / )                 .-.
         .-.      (__/    /        haha    _/oo \\
       _/ ..\       /     \               ( \v  /__
      ( \  u/__    /       \__             \/   ___)
       \    \__)   \_.-._._   )  .-.       /     \\
       /     \             `-`  / ee\_    /       \_
    __/       \               __\  o/ )   \_.-.__   )
   (   _._.-._/     hoho     (___   \/           '-'
jgs '-'                        /     \\
                             _/       \    teehee
                            (   __.-._/


        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Art by "JGS"
        ''')

    if titleChoice == 3:
        print('''
        ___
      _/ oo\\
     ( \  -/__
      \    \__)
      /     \\
jgs  /      _\\
    `"""""``

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Art by "JGS"
        ''')

    if titleChoice == 4:
        print('''

                        ,
                 \`-,      ,     =-
             .-._/   \_____)\
            ("              / =-
             '-;   ,_____.-'       =-
  jgs         /__.'

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Art by "JGS"
        ''')

    if titleChoice == 5:
        print ('''
   _______________                        |*\_/*|________
  |  ___________  |     .-.     .-.      ||_/-\_|______  |
  | |           | |    .****. .****.     | |           | |
  | |   0   0   | |    .*****.*****.     | |   0   0   | |
  | |     -     | |     .*********.      | |     -     | |
  | |   \___/   | |      .*******.       | |   \___/   | |
  | |___     ___| |       .*****.        | |___________| |
  |_____|\_/|_____|        .***.         |_______________|
    _|__|/ \|_|_.............*.............._|________|_
   / ********** \                          / ********** \\
 /  ************  \                      /  ************  \\
--------------------                    --------------------

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Artist Unknown.
        ''')

    if titleChoice == 6:
        print ('''
   _______________                        _______________
  |  ___________  |     .-.     .-.      |  ___________  |
  | |           | |    .****. .****.     | |           | |
  | |   0   0   | |    .*****.*****.     | |   0   0   | |
  | |     -     | |     .*********.      | |     -     | |
  | |   \___/   | |      .*******.       | |   \___/   | |
  | |___     ___| |       .*****.        | |___________| |
  |_____|\_/|_____|        .***.         |_______________|
    _|__|/ \|_|_.............*.............._|________|_
   / ********** \                          / ********** \\
 /  ************  \                      /  ************  \\
--------------------                    --------------------

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Artist Unknown.
        ''')

    if titleChoice == 7:
                print ('''
   |*\_/*|________                        |*\_/*|________
  ||_/-\_|______  |     .-.     .-.      ||_/-\_|______  |
  | |           | |    .****. .****.     | |           | |
  | |   0   0   | |    .*****.*****.     | |   0   0   | |
  | |     -     | |     .*********.      | |     -     | |
  | |   \___/   | |      .*******.       | |   \___/   | |
  | |___     ___| |       .*****.        | |___________| |
  |_____|\_/|_____|        .***.         |_______________|
    _|__|/ \|_|_.............*.............._|________|_
   / ********** \                          / ********** \\
 /  ************  \                      /  ************  \\
--------------------                    --------------------

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Artist Unknown.
        ''')

    if titleChoice == 8:
        print ('''
                       _ _       \ \\
    .-"""""-. / \_> /\    |/
   /         \.'`  `',.--//
 -(    Y2K    I      I  @@\\
   \         /'.____.'\___|
    '-.....-' __/ | \   (`)
jgs          /   /  /
                 \  \\

        Scarily Good SOC Toolkit
        Written by Jackson Nestler
        Art by "JGS"
        Turn your computer off before midnight on 12/31/99.
        ''')

