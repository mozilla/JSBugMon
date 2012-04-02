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
import traceback

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

    parser.add_option('-v', '--verbose',
                      dest='verbose',
                      action='store_true',
                      default=False,
                      help='Be verbose. Defaults to "False"')

    parser.add_option('-V', '--verify-fixed',
                      dest='verifyfixed',
                      action='store_true',
                      default=False,
                      help='Verify fix and comment. Defaults to "False"')

    parser.add_option('-C', '--confirm',
                      dest='confirm',
                      action='store_true',
                      default=False,
                      help='Attempt to confirm (or deny) open bugs. Defaults to "False"')

    parser.add_option('-U', '--update-bug',
                      dest='updatebug',
                      action='store_true',
                      default=False,
                      help='Update the bug. Defaults to "False"')

    parser.add_option('-P', '--update-bug-positive',
                      dest='updatebugpositive',
                      action='store_true',
                      default=False,
                      help='Update the bug also when it not changes state. Defaults to "False"')

    parser.add_option('-G', '--guess-opts',
                      dest='guessopts',
                      action='store_true',
                      default=False,
                      help='Force guessing the JS shell options. Defaults to "False"')

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
    bugmon = BugMonitor(API_ROOT, username, password, options.repobase, options)

    for bug_id in args:
      print "====== Analyzing bug " + str(bug_id) + " ======"
      try:
        if options.verifyfixed:
          bugmon.verifyFixedBug(bug_id, options.updatebug)
        elif options.confirm:
          bugmon.confirmOpenBug(bug_id, options.updatebug, options.updatebugpositive)
        else:
          result = bugmon.reproduceBug(bug_id)
      except Exception as e:
        if options.verbose:
          print "Caught exception: " + str(e)
          print traceback.format_exc()


class BugMonitorResult:
  # Different result states:
  #  FAILED               - Unable to reproduce on original revision
  #  REPRODUCED_FIXED     - Reproduced on original revision but not on tip (fixed on tip)
  #  REPRODUCED_TIP       - Reproduced on both revisions
  #  REPRODUCED_SWITCHED  - Reproduced on tip, but with a different crash/signal
  statusCodes = enum('FAILED', 'REPRODUCED_FIXED', 'REPRODUCED_TIP', 'REPRODUCED_SWITCHED')

  def __init__(self, branchName, origRev, tipRev, status):
    self.branchName = branchName
    self.origRev = origRev
    self.tipRev = tipRev
    self.status = status

class BugMonitor:

  def __init__(self, apiroot, username, password, repoBase, options):
    self.apiroot = apiroot
    self.bz = BugzillaAgent(apiroot, username, password)
    
    self.repoBase = repoBase

    # Here we store the tip revision per repository for caching purposes
    self.tipRev = {}

    self.guessopts = {}
    self.guessopts['mozilla-central'] = ['-m -n', '-m -n -a', '-m', '-j', '-j -m', '-j -m -a', None]
    self.guessopts['ionmonkey'] = ['--ion -n -m', '--ion -n -m --ion-eager', '--ion -n', '--ion -n --ion-eager', None]

    # Misc options
    self.options = options

  def postComment(self, bugnum, comment):
    url = urljoin(self.apiroot, 'bug/%s/comment?%s' % (bugnum, self.bz.qs()))
    return Comment(text=comment).post_to(url)

  def verifyFixedBug(self, bugnum, updateBug):
    # Fetch the bug
    bug = self.bz.get_bug(bugnum)

    if (bug.status == "RESOLVED" and bug.resolution == "FIXED"):
      result = self.reproduceBug(bugnum)

      if (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
        if updateBug:
          print "Marking bug " + str(bugnum) + " as verified fixed..."
          # Add a comment
          self.postComment(bugnum, "JSBugMon: This bug has been automatically verified fixed.")
          # Need to refetch the bug...
          bug = self.bz.get_bug(bugnum)
          # Mark VERIFIED FIXED now
          bug.status = "VERIFIED"
          bug.put()
        else:
          print "Would mark bug " + str(bugnum) + " as verified fixed..."

    return

  def confirmOpenBug(self, bugnum, updateBug, updateBugPositive):
    # Fetch the bug
    bug = self.bz.get_bug(bugnum)

    if (bug.status != "RESOLVED" and bug.status != "VERIFIED"):
      bugUpdateRequested = False
      bugConfirmRequested = False
      bugCloseRequested = False
      bugUpdated = False

      closeBug = False

      wbOpts = []
      if (bug.whiteboard != None):
        ret = re.compile('\[jsbugmon:([^\]]+)\]').search(bug.whiteboard)
        if (ret != None and ret.groups > 1):
          wbOpts = ret.group(1).split(",")

      # Explicitly marked to ignore this bug
      if ('ignore' in wbOpts):
        return

      if ('update' in wbOpts):
        bugUpdateRequested = True

      if ('reconfirm' in wbOpts):
        bugConfirmRequested = True

      if ('close' in wbOpts):
        bugCloseRequested = True

      result = self.reproduceBug(bugnum)

      if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP):
        if updateBugPositive or bugConfirmRequested:
          print "Marking bug " + str(bugnum) + " as confirmed on tip..."
          # Add a comment
          self.postComment(bugnum, "JSBugMon: This bug has been automatically confirmed to be still valid (reproduced on revision " + result.tipRev + ").")
          bugUpdated = True
        else:
          print "Would mark bug " + str(bugnum) + " as confirmed on tip..."
      elif (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
        if updateBug or bugUpdateRequested:
          print "Marking bug " + str(bugnum) + " as non-reproducing on tip..."
          # Add a comment
          self.postComment(bugnum, "JSBugMon: The testcase found in this bug no longer reproduces (tried revision " + result.tipRev + ").")
          bugUpdated = True

          # Close bug only if requested to do so
          closeBug = bugCloseRequested
        else:
          print "Would mark bug " + str(bugnum) + " as non-reproducing on tip..."

      if bugUpdated:
        # Fetch the bug again for updating
        bug = self.bz.get_bug(bugnum)

        # We add "ignore" to our bugmon options so we don't update the bug a second time
        wbOpts.append('ignore')
        wbParts = filter(lambda x: len(x) > 0, map(str.rstrip, map(str.lstrip, re.split('\[jsbugmon:[^\]]+\]', bug.whiteboard))))
        wbParts.append("[jsbugmon:" + ",".join(wbOpts) + "]")
        bug.whiteboard = " ".join(wbParts)

        # Mark bug as WORKSFORME if confirmed to no longer reproduce
        if closeBug:
          bug.status = "RESOLVED"
          bug.resolution = "WORKSFORME"

        bug.put()


    return


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

    opts = None
    tipOpts = None

    # Isolate options for testing, not explicitly instructed to guess
    if not self.options.guessopts:
      opts = self.extractOptions(text)
      if (opts == None):
        print "Warning: No options found, will try to guess"

    arch = None
    archList = None
    if (bug.platform == "x86_64"):
      arch = "64"
    elif (bug.platform == "x86"):
      arch = "32"
    elif (bug.platform == "All"):
      arch = "64"
      archList = [ "64", "32" ] # TODO: Detect native platform here
    else:
      raise Exception("Error: Unsupported architecture \"" + bug.platform + "\" required by bug")

    if (bug.version == "Trunk"):
      reponame = "mozilla-central"
    elif (bug.version == "Other Branch"):
      reponame = "ionmonkey"
    else:
      raise Exception("Error: Unsupported branch \"" + bug.version + "\" required by bug")

    repoDir = os.path.join(self.repoBase, reponame)

    # We need at least some shell to extract the test from the bug, 
    # so we build a debug tip shell here already
    updated = False
    if not self.tipRev.has_key(repoDir):
      # If we don't know the tip revision for this branch, update and get it
      self.tipRev[repoDir] = self.hgUpdate(repoDir)
      updated = True
    (tipShell, tipRev) = self.getShell("cache/", arch, "dbg", 0, self.tipRev[repoDir], updated, repoDir)

    # If the file already exists, then we can reuse it
    testFile = "bug" + str(bugnum) + ".js"

    if (os.path.exists(testFile)):
      print "Using existing (cached) testfile " + testFile
    else:

      # We need to detect where our test is.
      blocks = text.split("\n\n")
      found = False
      cnt = 0
      for i,block in enumerate(blocks):
        # Write our test to file
        outFile = open(testFile, "w")
        outFile.write(block)
        outFile.close()
        (err, ret) = testBinary(tipShell, testFile, [], 0, timeout=30)

        if (err.find("SyntaxError") < 0):
          # We have found the test (or maybe only the start of the test)
          # Try adding more code until we hit an error or are out of
          # blocks.
          oldBlock = block
          curBlock = block
          for j,block in enumerate(blocks):
            if j > i:
              curBlock = curBlock + "\n" + block
              # Write our test to file
              outFile = open(testFile, "w")
              outFile.write(curBlock)
              outFile.close()
              (err, ret) = testBinary(tipShell, testFile, [], 0, timeout=30)
              if (err.find("SyntaxError") >= 0):
                # Too much, write oldBlock and break
                outFile = open(testFile, "w")
                outFile.write(oldBlock)
                outFile.close()
                break
              else:
                oldBlock = curBlock

          found = True
          print "Isolated possible testcase starting in textblock " + str(cnt)
          break
        cnt += 1
      if not found:
        # Ensure we don't cache the wrong test
        os.remove(testFile)
        raise Exception("Error: Failed to isolate test from comment")

    (oouterr, oret) = (None, None)
    (origShell, origRev) = (None, None)

    # If we have an exact architecture, we will only test that
    if (archList == None):
      archList = [ arch ]

    for compileType in ['dbg', 'opt']:
      for archType in archList:
        # Update to tip and cache result:
        updated = False
        if not self.tipRev.has_key(repoDir):
          # If we don't know the tip revision for this branch, update and get it
          self.tipRev[repoDir] = self.hgUpdate(repoDir)
          updated = True
      
        (tipShell, tipRev) = self.getShell("cache/", archType, compileType, 0, self.tipRev[repoDir], updated, repoDir)
        (origShell, origRev) = self.getShell("cache/", archType, compileType, 0, rev, False, repoDir)


        if (opts != None):
          (oouterr, oret) = testBinary(origShell, testFile, opts , 0, verbose=self.options.verbose, timeout=30)
        else:
          print "Guessing options...",
          guessopts = self.guessopts[reponame]
          for opt in guessopts:
            topts = []
            if opt == None:
              print " no options",
            else:
              print " " + opt,
              topts = opt.split(' ')
            (oouterr, oret) = testBinary(origShell, testFile, topts , 0, verbose=self.options.verbose, timeout=30)
            if (oret < 0):
              opts = topts
              break;

        # If we reproduced with one arch, then we don't need to try the others
        if (oret < 0):
          break;

      # If we reproduced with dbg, then we don't need to try opt
      if (oret < 0):
        break;

    # Check if we reproduced at all (dbg or opt)
    if (oret < 0):
      print ""
      print "Successfully reproduced bug (exit code " + str(oret) + ") on original revision " + rev + ":"
      errl = oouterr.split("\n")
      if len(errl) > 2: errl = errl[-2:]
      for err in errl:
        print err

      if (opts != None):
        # Try running on tip now
        print "Testing bug on tip..."
        if self.options.guessopts:
          guessopts = self.guessopts[reponame]
          for opt in guessopts:
            tipOpts = []
            if opt == None:
              print " no options",
            else:
              print " " + opt,
              tipOpts = opt.split(' ')
            (touterr, tret) = testBinary(tipShell, testFile, tipOpts , 0, verbose=self.options.verbose, timeout=30)
            if (tret < 0):
              break;
        else:
          tipOpts = opts
          (touterr, tret) = testBinary(tipShell, testFile, tipOpts , 0, verbose=self.options.verbose, timeout=30)
      else:
        print ""

      if (tret < 0):
        if (tret == oret):
          if (opts == tipOpts):
            print "Result: Bug still reproduces"
            return BugMonitorResult(reponame, rev, self.tipRev[repoDir], BugMonitorResult.statusCodes.REPRODUCED_TIP)
          else:
            print "Result: Bug still reproduces, but with different options: " + " ".join(tipOpts) # TODO need another code here in the future
            return BugMonitorResult(reponame, rev, self.tipRev[repoDir], BugMonitorResult.statusCodes.REPRODUCED_TIP)
        else:
          # Unlikely but possible, switched signal
          print "Result: Bug now reproduces with signal " + str(tret) + " (previously " + str(oret) + ")"
          return BugMonitorResult(reponame, rev, self.tipRev[repoDir], BugMonitorResult.statusCodes.REPRODUCED_SWITCHED)
      else:
        print "Result: Bug no longer reproduces"
        return BugMonitorResult(reponame, rev, self.tipRev[repoDir], BugMonitorResult.statusCodes.REPRODUCED_FIXED)
    else:
      print "Error: Failed to reproduce bug on original revision"
      return BugMonitorResult(reponame, rev, self.tipRev[repoDir], BugMonitorResult.statusCodes.FAILED)

  def extractOptions(self, text):
      ret = re.compile('((?: \-[a-z])+)', re.DOTALL).search(text)
      if (ret != None and ret.groups > 1):
        return ret.group(1).lstrip().split(" ")
      
      return None

  def extractRevision(self, text):
      if (text == None):
        return None
      tokens = text.split(' ')
      for token in tokens:
        if (re.match('^[a-f0-9]{12}[^a-f0-9]?', token)):
          return token[0:12]
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

  def getShell(self, shellCacheDir, archNum, compileType, valgrindSupport, rev, updated, repoDir):
    shell = self.getCachedShell(shellCacheDir, archNum, compileType, valgrindSupport, rev)
    updRev = None
    if (shell == None):
      if updated:
        updRev = rev
      else:
        updRev = self.hgUpdate(repoDir, rev)


      if (rev == None):
        print "Compiling a new shell for tip (revision " + updRev + ")"
      else:
        print "Compiling a new shell for revision " + updRev
      shell = makeShell(shellCacheDir, repoDir, archNum, compileType, valgrindSupport, updRev, True)

    return (shell, updRev)

if __name__ == '__main__':
    main()
