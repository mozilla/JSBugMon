#!/usr/bin/env python
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Original Code is ADBFuzz.
#
# The Initial Developer of the Original Code is Christian Holler (decoder).
#
# Contributors:
#  Christian Holler <decoder@mozilla.com> (Original Developer)
#
# ***** END LICENSE BLOCK *****

import sys
import os
import subprocess

from bugzilla.agents import BMOAgent
from bugzilla.utils import get_credentials

# We can use "None" for both instead to not authenticate
username, password = get_credentials()

# Load our agent for BMO
bmo = BMOAgent(username, password)

# Search for all fixed JS engine bugs that have a security impact
options = {
    # Must be a JS Engine bug which is RESOLVED FIXED
    'component':        'JavaScript Engine',
    'product':          'Core',
    'bug_status':       'RESOLVED',
    'resolution':       'FIXED',
    # Ignore old bugs, should be fixed at most 30 days ago
    'chfieldto':        'Now',
    'chfieldfrom':      '-30d',
    'chfield':          'resolution',
    'chfieldvalue':     'FIXED',
     # Advanced search criteria
    'query_format':     'advanced',
     # Should either be a core-security bug
    'field0-0-0':       'bug_group',
    'type0-0-0':        'substring',
    'value0-0-0':       'core-security',
     # or have an [sg: tag in whiteboard
    'type0-0-1':        'regexp',
    'field0-0-1':       'status_whiteboard',
    'value0-0-1':       '\[sg:(critical|high|moderate|low)',
    # or have a sec- keyword 
    'type0-0-2':        'regexp',
    'field0-0-2':       'keywords',
    'value0-0-2':       '(sec-critical|sec-high|sec-moderate|sec-low)',
    'include_fields':   '_default',
}

# Get the bugs from the api
buglist = bmo.get_bug_list(options)

if len(buglist) == 0:
  print "No bugs found."
  sys.exit(0)

print "Found %s bugs:" % (len(buglist))

# Basic arguments
cmd = ['python', os.path.join(sys.path[0], 'bugmon.py'), '-r', os.path.join(sys.path[0], 'repos/'), "-V", "-G" ]

# Propagate all extra arguments
cmd.extend(sys.argv[1:])

# Append bug numbers
for bug in buglist:
    print bug
    cmd.append(str(bug.id))

# Print command
print " ".join(cmd)

# Run command
sys.exit(subprocess.call(cmd))
