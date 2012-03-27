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

import base64
import itertools
import os
import argparse
import re
import platform
import subprocess

from optparse import OptionParser

from compileShell import makeShell, shellName, testBinary
from subprocesses import captureStdout

from bugzilla.models import Bug, Attachment, Flag, User, Comment
from bugzilla.agents import BugzillaAgent
from bugzilla.utils import urljoin, qs, get_credentials, FILE_TYPES

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

def parseOpts():
    usage = 'Usage: %prog [options] bugid [bugid ..]'
    parser = OptionParser(usage)
    # See http://docs.python.org/library/optparse.html#optparse.OptionParser.disable_interspersed_args
    parser.disable_interspersed_args()

    # Define the repository base.
    parser.add_option('-r', '--repobase',
                      dest='repobase',
                      default=None,
                      help='Repository base directory, mandatory.')

    # Enable valgrind support.
    parser.add_option('-v', '--verbose',
                      dest='verbose',
                      action='store_true',
                      default=False,
                      help='Be verbose. Defaults to "False"')

    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error('Not enough arguments')
  
    return (options, args)

def main():
    # Script options
    (options, args) = parseOpts()

    # Get the API root, default to bugzilla.mozilla.org
    API_ROOT = os.environ.get('BZ_API_ROOT',
                              'https://api-dev.bugzilla.mozilla.org/latest/')

    # Authenticate
    username, password = get_credentials()

    # Sample run
    bugmon = BugMonitor(API_ROOT, username, password, options.repobase)

    for bug_id in args:
      print "====== Analyzing bug " + str(bug_id) + " ======"
      try:
        print bugmon.reproduceBug(bug_id)
      except Exception as e:
        print "Caught exception: " + str(e)


class BugMonitor:

  def __init__(self, api, username, password, repoBase):
    self.bz = BugzillaAgent(api, username, password)
    
    # Different result states:
    #  FAILED               - Unable to reproduce on original revision
    #  REPRODUCED_FIXED     - Reproduced on original revision but not on tip (fixed on tip)
    #  REPRODUCED_TIP       - Reproduced on both revisions
    #  REPRODUCED_SWITCHED  - Reproduced on tip, but with a different crash/signal
    self.result = enum('FAILED', 'REPRODUCED_FIXED', 'REPRODUCED_TIP', 'REPRODUCED_SWITCHED')

    self.repoBase = repoBase

    # Here we store the tip revision per repository for caching purposes
    self.tipRev = {}

  def reproduceBug(self, bugnum):
    # Fetch the bug
    bug = self.bz.get_bug(bugnum)

    # Look for the first comment
    comment = bug.comments[0] if len(bug.comments) > 0 else None

    if (comment == None):
      raise Exception("Error: Specified bug does not have any comments")

    text = comment.text

    # Isolate revision to test for
    rev = self.extractRevision(text)

    if (rev == None):
      raise Exception("Error: Failed to isolate original revision for test")

    # Isolate options for testing
    opts = self.extractOptions(text)

    if (opts == None):
      print "Warning: No options found, will try to guess"
      #opts = []
      #raise Exception("Error: Failed to isolate options from comment")

    arch = None
    if (bug.platform == "x86_64"):
      arch = "64"
    elif (bug.platform == "x86"):
      arch = "32"
    elif (bug.platform == "All"):
      arch = "64" # TODO: Detect native platform here
    else:
      raise Exception("Error: Unsupported architecture \"" + bug.platform + "\" required by bug")

    if (bug.version == "Trunk"):
      reponame = "mozilla-central"
    else:
      raise Exception("Error: Unsupported branch \"" + bug.version + "\" required by bug")

    repoDir = os.path.join(self.repoBase, reponame)

    updated = False
    if not self.tipRev.has_key(repoDir):
      # If we don't know the tip revision for this branch, update and get it
      self.tipRev[repoDir] = self.hgUpdate(repoDir)
      updated = True
    
    tipShell = self.getCachedShell("cache/", arch, "dbg", 0, self.tipRev[repoDir])
    if (tipShell == None):
      # If there is no cached shell, but we did not update earlier, then we need
      # to do it now to ensure we're compiling the correct version!
      # This can happen if we request another architecture for example.
      if not updated:
        self.tipRev[repoDir] = self.hgUpdate(repoDir)
      print "Compiling a new shell for tip (revision " + self.tipRev[repoDir] + ")"
      tipShell = makeShell("cache/", repoDir, arch, "dbg", 0, self.tipRev[repoDir])

    origRev = self.hgUpdate(repoDir, rev)

    origShell = self.getCachedShell("cache/", arch, "dbg", 0, rev)
    if (origShell == None):
      print "Compiling a new shell for orig (revision " + rev + ")"
      origShell = makeShell("cache/", repoDir, arch, "dbg", 0, rev)

    # If the file already exists, then we can reuse it

    testFile = "bug" + str(bugnum) + ".js"

    if (os.path.exists(testFile)):
      print "Using existing (cached) testfile " + testFile
    else:
      # We need to detect where our test is.
      blocks = text.split("\n\n")
      found = False
      cnt = 0
      for block in blocks:
        # Write our test to file
        outFile = open(testFile, "w")
        outFile.write(block)
        outFile.close()
        (err, ret) = testBinary(origShell, testFile, [], 0)

        if (err.find("SyntaxError") < 0):
          found = True
          print "Isolated possible testcase in textblock " + str(cnt)
          break
        cnt += 1
      if not found:
        raise Exception("Error: Failed to isolate test from comment")

    oouterr = None
    oret = None

    if (opts != None):
      (oouterr, oret) = testBinary(origShell, testFile, opts , 0)
    else:
      print "Guessing options...",
      guessopts = ['-m -n', '-m -n -a', '-m', '-j', '-j -m', '-j -m -a', '']
      for opt in guessopts:
        print " " + opt,
        opts = opt.split(' ')
        (oouterr, oret) = testBinary(origShell, testFile, opts , 0)
        if (oret < 0):
          break;

    if (oret < 0):
      print ""
      print "Successfully reproduced bug (exit code " + str(oret) + ") on original revision " + rev + ":"
      print oouterr

    if (opts != None):
      # Try running on tip now
      print "Testing bug on tip..."
      (touterr, tret) = testBinary(tipShell, testFile, opts , 0)
    else:
      print ""

    if (oret < 0):
      if (tret < 0):
        if (tret == oret):
          print "Result: Bug still reproduces"
          return self.result.REPRODUCED_TIP
        else:
          # Unlikely but possible, switched signal
          print "Result: Bug now reproduces with signal " + str(tret) + " (previously " + str(oret) + ")"
          return self.result.REPRODUCED_SWITCHED
      else:
        print "Result: Bug no longer reproduces"
        return self.result.REPRODUCED_FIXED
    else:
      print "Error: Failed to reproduce bug on original revision"
      return self.result.FAILED

  def extractOptions(self, text):
      ret = re.compile('((?: \-[a-z])+)', re.DOTALL).search(text)
      if (ret != None and ret.groups > 1):
        return ret.group(1).lstrip().split(" ")
      
      return None

  def extractRevision(self, text):
      tokens = text.split(' ')
      for token in tokens:
        if (re.match('^[a-f0-9]{12}[^a-f0-9]?', token)):
          return token[0:11]
      return None

  def hgUpdate(self, repoDir, rev=None):
      print "Running hg update..."
      if (rev != None):
          captureStdout(['hg', 'update', '-r', rev], ignoreStderr=True, currWorkingDir=repoDir)
      else:
          captureStdout(['hg', 'update'], ignoreStderr=True, currWorkingDir=repoDir)

      hgIdCmdList = ['hg', 'identify', repoDir]
      # In Windows, this throws up a warning about failing to set color mode to win32.
      if platform.system() == 'Windows':
          hgIdFull = captureStdout(hgIdCmdList, currWorkingDir=repoDir, ignoreStderr=True)[0]
      else:
          hgIdFull = captureStdout(hgIdCmdList, currWorkingDir=repoDir)[0]
      hgIdChangesetHash = hgIdFull.split(' ')[0]

      #os.chdir(savedPath)
      return hgIdChangesetHash

  def getCachedShell(self, shellCacheDir, archNum, compileType, valgrindSupport, rev):
      cachedShell = os.path.join(shellCacheDir, shellName(archNum, compileType, rev, valgrindSupport))
      if os.path.exists(cachedShell):
          return cachedShell
      return None

if __name__ == '__main__':
    main()
