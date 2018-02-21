#!/bin/bash

# PUA configuration file
# By leaving NONINTERACTIVE blank and setting the VIPs you may pre-stage IP addresses in the
# various VIP configuration options for semi-automatic operation
#
# For full non-interactive use, NONINTERACTIVE must be set to "y"

NONINTERACTIVE="" # y or empty for no
WebSSH2VIP="192.168.20.62" # dedicated IP address
RADIUSVIP="192.168.20.63" # the next 4 IP addresses can be shared
LDAPVIP="192.168.20.63"
LDAPSVIP="192.168.20.63"
WebtopVIP="192.168.20.63"

# RADIUS Testimng option y/n Configure the BIG-IP for RADIUS auth to itself.
# If used with NONINTERACTIVE unset, this will not be semi-automatic and will result in
# The BIG-IP being configured for RADIUS auth against itself.
# RadiusConfig="y"

# In case you have some weird responses from /var/prompt/ps1 and want to force run
# not a good idea to do this unless you know what you're doing.
# STATUS="Active"

# If you're downloading this file with Windows, make sure to run it through `dos2unix` or something to
# fix the linefeed characters that Windows feels compelled to add. Best to use curl if you can
# help it.
