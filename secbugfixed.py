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

from bugzilla.agents import BMOAgent
from bugzilla.utils import get_credentials

# We can use "None" for both instead to not authenticate
username, password = get_credentials()

# Load our agent for BMO
bmo = BMOAgent(username, password)

# Search for all fixed JS engine bugs that have a security impact
options = {
    'component':        'JavaScript Engine',
    'product':          'Core',
    'bug_status':       'RESOLVED',
    'resolution':       'FIXED',
    'query_format':     'advanced',
    'field0-0-0':       'bug_group',
    'type0-0-0':        'substring',
    'value0-0-0':       'core-security',
    'type0-0-1':        'regexp',
    'field0-0-1':       'status_whiteboard',
    'value0-0-1':       '\[sg:(critical|high|moderate|low)',
    'include_fields':   '_default',
}

# Get the bugs from the api
buglist = bmo.get_bug_list(options)

print "Found %s bugs" % (len(buglist))

# Basic arguments
cmd = ['python', os.path.join(sys.path[0], 'bugmon.py'), '-r', os.path.join(sys.path[0], 'repos/'), "-V", "-G" ]

# Propagate all extra arguments
cmd.extend(sys.argv[1:])

# Append bug numbers
for bug in buglist:
    cmd.append(str(bug.id))

# Print command
print " ".join(cmd)
