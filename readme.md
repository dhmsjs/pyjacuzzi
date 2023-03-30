jacuzzi.py and jacuzziui.py
===========================

The jacuzzi.py module module extends pybalboa to work instead with Jacuzzi spas. It uses pybalboa-0.13 from https://github.com/garbled1/pybalboa. It monitors and controls a jacuzzi spa via a WiFi link.

That hardware connection is provided by Jacuzzi's Prolink module. Jacuzzi has replaced Prolink with SmartTub -- which communicates to their cloud via the cell network. Jacuzzi does still provide Prolink modules for those locations where cell signals are weak.

However the Prolink module appears to be little more than a WiFi-to-RS485 converter; I suspect with a little work someone could replace Prolink with a COTS WiFi-to-RS485 device anyway.

The jacuzziui.py module is a simple text-windowing console (i.e. command line) app that runs jacuzzi.py in the background, allowing a user to both monitor and control the jacuzzi spa via a WiFi link.

# Purpose

The long-term goal here is to for jacuzzi.py to be an interface between Jacuzzi brand spas and Home Assistant, without the need for Prolink or SmartTub, in the same way that balboa.py currently provides that interface to Balboa brand spas.

I chose to extend pybalboa so that I could leverage the already-proven WiFi and protocol parsing behavior in pybalboa. This dependency turns out to be pretty light; it would not take major effort to decouple jacuzzi.py from pybalboa. Still, I am deeply indebted to: 

* garbled1 (https://github.com/garbled1/pybalboa)
* natekspencer (https://github.com/natekspencer)
* ccutrer (https://github.com/ccutrer/balboa_worldwide_app/wiki)

along with several others here unnamed, who have helped reverse engineer balboa hot tub control systems and their many rebranded derivatives.

Note that as of Jan 2023 pybalboa has undergone significant revisions beyond version 0.13. I doubt jacuzzi.py will work with anything later than v0.13 without careful attention -- which given the light dependency, is probably not worth the effort.

Tested on a Raspberry PI4 running Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-1082-raspi aarch64), accessed via puTTY.

# Documentation

The /docs subdirectory contains several useful sources of reference information I have compiled.

* ProlinkMessageTypes.txt -- This document summarizes my research on the specific message types and data packet contents found in Jacuzzi spas and specific differences with similar Balboa message packets. It also documents some of the process I used to get there.

* ProlinkMessageParsing.txt -- This documents the specific details of Prolink message packets. The information here comes from analysis of the decompiled Prolink app itself.

* ProlinkDecompiledCodeRaw.txt -- This document is (some of) the actual Prolink source code decompiled, with comments I added as I worked through understanding it.

# To run jacuzziui.py

1. Use Jacuzzi's Prolink module (or develop a substitute) to connect your Jacuzzi spa to your local network.

2. Place the four source files on a machine that also has a connection to that same local network.

3. Modify the ip address constant at the top of jacuzziui.py to match your spa's local ip address.

4. In that directory, open a terminal window and expand it to fill most, if not all of your screen.

5. Type "python3 jacuzziui.py" at the command prompt to run the user interface. The message window will show new (unique) packets both sent and received. The menu window tells you how to navigate. Press Ctrl-x to quit.

6. If jacuzzi.py cannot connect to the spa, it may be because Prolink has gone to sleep. This seems to happen when the spa is unused for awhile. You might try using the topside panel to turn pumps on and off, etc, in order to try to wake Prolink up. 

7. It also seems to connect reliably whenever the spa is performing a filter cycle, so you can try timing your test to coincide with one of those.

# Disclaimers

1. While I am not new to programming, I am relatively new to Python, git and Github -- so please be nice!  I welcome your corrections, suggestions, improvements, and feedback (particularly when it is constructive).

2. If you are one of those folks who love sparse code without comments, you will be disappointed. Sorry (not sorry).

