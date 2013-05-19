#!/bin/sh
source ./config

#
# Use http://www.hidemyass.com/anonymous-email
#

megareg --agree --email megatools2@hmamail.com --name MegaTools --password qweqweqwe

#
# Continue from there on, as queried on the command line
#

megareg --agree --anonymous --password qweqweqwe

#
# Non-interactive
#

#megareg --non-interactive --email megatools3@hmamail.com --name MegaTools --password qweqweqwe
