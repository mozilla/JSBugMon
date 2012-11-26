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
import time

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

    parser.add_option('-p', '--process',
                      dest='process',
                      action='store_true',
                      default=False,
                      help='Process commands on whiteboard of the bug. Defaults to "False"')

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
        elif options.process:
          bugmon.processCommand(bug_id)
        else:
          raise "Unsupported action requested"
          #result = bugmon.reproduceBug(bug_id)
      except BugException as b:
        print "Cannot process bug: " + str(b)
      except Exception as e:
        print "Caught exception: " + str(e)
        print traceback.format_exc()


class BugException(Exception):
  pass

class BugMonitorResult:
  # Different result states:
  #  FAILED               - Unable to reproduce on original revision
  #  REPRODUCED_FIXED     - Reproduced on original revision but not on tip (fixed on tip)
  #  REPRODUCED_TIP       - Reproduced on both revisions
  #  REPRODUCED_SWITCHED  - Reproduced on tip, but with a different crash/signal
  statusCodes = enum('FAILED', 'REPRODUCED_FIXED', 'REPRODUCED_TIP', 'REPRODUCED_SWITCHED')

  def __init__(self, branchName, origRev, tipRev, testFlags, testPath, arch, ctype, status):
    self.branchName = branchName
    self.origRev = origRev
    self.tipRev = tipRev
    self.testFlags = testFlags
    self.testPath = testPath
    self.arch = arch
    self.ctype = ctype
    self.status = status

class BugMonitor:

  def __init__(self, apiroot, username, password, repoBase, options):
    self.apiroot = apiroot
    self.bz = BugzillaAgent(apiroot, username, password)
    
    self.repoBase = repoBase

    # Here we store the tip revision per repository for caching purposes
    self.tipRev = {}

    self.guessopts = {}
    #self.guessopts['mozilla-central'] = ['-m -n', '-m -n -a', '-m', '-j', '-j -m', '-j -m -a', None]
    #self.guessopts['ionmonkey'] = ['--ion -n -m', '--ion -n -m --ion-eager', None, '--ion-eager']
    self.guessopts['ionmonkey'] = ['--ion -n -m', '--ion -n -m -a', '--ion -n -m --ion-eager', '--ion -n -m --ion-eager -a' ]
    self.guessopts['mozilla-central'] = [None, '--ion-eager', '-m --ion-eager', '-m -a --ion-eager', '--no-ion', '-a', '-a --no-ion', '-a --no-ti', '-m -n', '-m -n -a', '-m', '-j', '-j -m', '-j -m -a']

    # Misc options
    self.options = options

  def fetchBug(self, bug_id):
    bug = self.bz.get_bug(bug_id)
    if len(bug.depends_on) > 0:
      if isinstance(bug.depends_on[0], str):
        bug.depends_on = [ int("".join(bug.depends_on)) ]

    if bug.cf_crash_signature != None:
      bug.cf_crash_signature = bug.cf_crash_signature.replace("\r\n", "\n")

    return bug

  def postComment(self, bugnum, comment):
    url = urljoin(self.apiroot, 'bug/%s/comment?%s' % (bugnum, self.bz.qs()))
    return Comment(text=comment).post_to(url)

  def verifyFixedBug(self, bugnum, updateBug):
    # Fetch the bug
    bug = self.fetchBug(bugnum)

    if (bug.status == "RESOLVED" and bug.resolution == "FIXED"):
      result = self.reproduceBug(bug)

      if (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
        if updateBug:
          print "Marking bug " + str(bugnum) + " as verified fixed..."
          while True:
            try:
              bug = self.fetchBug(bugnum)
              # Mark VERIFIED FIXED now
              bug.status = "VERIFIED"
              bug.put()
              break
            except:
              print "Failed to submit bug change, sleeping one second and retrying..."
              time.sleep(1)

          # Add a comment
          self.postComment(bugnum, "JSBugMon: This bug has been automatically verified fixed.")
        else:
          print "Would mark bug " + str(bugnum) + " as verified fixed..."

    return

  def confirmOpenBug(self, bugnum, updateBug, updateBugPositive):
    # Fetch the bug
    bug = self.fetchBug(bugnum)

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

      result = self.reproduceBug(bug)

      comments = []

      if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP):
        if updateBugPositive or bugConfirmRequested:
          print "Marking bug " + str(bugnum) + " as confirmed on tip..."
          # Add a comment
          comments.append("JSBugMon: This bug has been automatically confirmed to be still valid (reproduced on revision " + result.tipRev + ").")
          bugUpdated = True
        else:
          print "Would mark bug " + str(bugnum) + " as confirmed on tip..."
      elif (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
        if updateBug or bugUpdateRequested:
          print "Marking bug " + str(bugnum) + " as non-reproducing on tip..."
          # Add a comment
          comments.append("JSBugMon: The testcase found in this bug no longer reproduces (tried revision " + result.tipRev + ").")
          bugUpdated = True

          # Close bug only if requested to do so
          closeBug = bugCloseRequested
        else:
          print "Would mark bug " + str(bugnum) + " as non-reproducing on tip..."

      if bugUpdated:
        wbOpts.append('ignore')
        wbParts = filter(lambda x: len(x) > 0, map(str.rstrip, map(str.lstrip, re.split('\[jsbugmon:[^\]]+\]', bug.whiteboard))))
        wbParts.append("[jsbugmon:" + ",".join(wbOpts) + "]")

        while True:
          try:
            # Fetch the bug again for updating
            bug = self.fetchBug(bugnum)

            # We add "ignore" to our bugmon options so we don't update the bug a second time
            bug.whiteboard = " ".join(wbParts)

            # Mark bug as WORKSFORME if confirmed to no longer reproduce
            if closeBug:
              bug.status = "RESOLVED"
              bug.resolution = "WORKSFORME"

            bug.put()
            break
          except:
            print "Failed to submit bug change, sleeping one second and retrying..."
            time.sleep(1)

      if (len(comments) > 0):
        comment = "\n".join(comments)
        print "Posting comment: "
        print comment
        print ""
        self.postComment(bugnum, comment)

    return

  def processCommand(self, bugnum):
    # Fetch the bug
    bug = self.fetchBug(bugnum)

    bugUpdateRequested = False
    bugConfirmRequested = False
    bugCloseRequested = False
    bugVerifyRequested = False
    bugBisectRequested = False
    bugBisectFixRequested = False
    bugUpdated = False

    closeBug = False
    verifyBug = False

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

      if ('verify' in wbOpts):
        bugVerifyRequested = True

      if ('bisect' in wbOpts):
        bugBisectRequested = True

      if ('bisectfix' in wbOpts):
        bugBisectFixRequested = True
        
      print wbOpts

      comments = []

      # Keep bisect comments separate so we can remove bisect/bisectfix commands separately
      bisectComments = []
      bisectFixComments = []

      result = None

      for opt in wbOpts:
        if (opt.find("=") > 0):
          (cmd,param) = opt.split('=')
          if (cmd != None and param != None):
            if (cmd == "verify-branch"):
              branches = param.split(';');
              for branch in branches:
                print "Branch " + branch
                branchResult = self.reproduceBug(bug, branch)
                if (branchResult.status == BugMonitorResult.statusCodes.REPRODUCED_TIP):
                  print "Marking bug " + str(bugnum) + " as reproducing on branch " + branch + " ..."
                  # Add a comment
                  comments.append("JSBugMon: This bug has been automatically confirmed to be still valid on branch " + branch + "  (reproduced on revision " + branchResult.tipRev + ").")
                elif (branchResult.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
                  print "Marking bug " + str(bugnum) + " as non-reproducing on branch " + branch + " ..."
                  comments.append("JSBugMon: The testcase found in this bug does not reproduce on branch " + branch + " (tried revision " + branchResult.tipRev + ").")
                else:
                  print "Marking bug " + str(bugnum) + " as not processable ..."
                  comments.append("JSBugMon: Command failed during processing this bug: " + opt + " (branch " + branch + ")")

      if bugVerifyRequested: 
        if bug.status == "RESOLVED":
          if result == None:
            result = self.reproduceBug(bug)
          if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP):
            print "Marking bug " + str(bugnum) + " as cannot verify fixed..."
            # Add a comment
            comments.append("JSBugMon: Cannot confirm fix, issue is still valid. (tried revision " + result.tipRev + ").")
          elif (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
            print "Marking bug " + str(bugnum) + " as verified fixed..."
            comments.append("JSBugMon: This bug has been automatically verified fixed. (tried revision " + result.tipRev + ").")
            verifyBug = True
          else:
            print "Marking bug " + str(bugnum) + " as not processable ..."
            comments.append("JSBugMon: Command failed during processing this bug: verify")

      if bugUpdateRequested:
        if bug.status != "RESOLVED" and bug.status != "VERIFIED":
          if result == None:
            result = self.reproduceBug(bug)
          if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP):
            if bugConfirmRequested:
              print "Marking bug " + str(bugnum) + " as confirmed on tip..."
              # Add a comment
              comments.append("JSBugMon: This bug has been automatically confirmed to be still valid (reproduced on revision " + result.tipRev + ").")
          
          elif (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
            print "Marking bug " + str(bugnum) + " as non-reproducing on tip..."
            # Add a comment
            comments.append("JSBugMon: The testcase found in this bug no longer reproduces (tried revision " + result.tipRev + ").")
            if bugCloseRequested:
              closeBug = True

      if bugBisectRequested and bug.status != "RESOLVED" and bug.status != "VERIFIED":
        if result == None:
          result = self.reproduceBug(bug)
        if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP or result.status == BugMonitorResult.statusCodes.REPRODUCED_SWITCHED or BugMonitorResult.statusCodes.REPRODUCED_FIXED):
          print "Bisecting bug " +  str(bugnum) + " ..."
          bisectComment = self.bisectBug(bugnum, result)
          print bisectComment
          if len(bisectComment) > 0:
            bisectComments.append("JSBugMon: Bisection requested, result:")
            bisectComments.extend(bisectComment)
          else:
            bisectComments.append("JSBugMon: Bisection requested, failed due to error (try manually).")
            bisectComments.append("");

      if bugBisectFixRequested:
        if result == None:
          result = self.reproduceBug(bug)
        if (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
          print "Bisecting fix for bug " +  str(bugnum) + " ..."
          bisectComment = self.bisectBug(bugnum, result, True)
          print bisectComment
          if len(bisectComment) > 0:
            bisectFixComments.append("JSBugMon: Fix Bisection requested, result:")
            bisectFixComments.extend(bisectComment)
          else:
            bisectFixComments.append("JSBugMon: Fix Bisection requested, failed due to error (try manually).")
            bisectFixComments.append("");

      wbParts = []
      whiteBoardModified = False
      if closeBug or verifyBug or len(comments) > 0:
        whiteBoardModified = True
        wbOpts.append('ignore')

      if bugBisectRequested:
        whiteBoardModified = True
        wbOpts.remove('bisect')
        comments.extend(bisectComments)

      if bugBisectFixRequested and len(bisectFixComments) > 0:
        whiteBoardModified = True
        wbOpts.remove('bisectfix')
        comments.extend(bisectFixComments)

      if whiteBoardModified:
        wbParts = filter(lambda x: len(x) > 0, map(str.rstrip, map(str.lstrip, re.split('\[jsbugmon:[^\]]+\]', bug.whiteboard))))
        wbParts.append("[jsbugmon:" + ",".join(wbOpts) + "]")

      while True:
        # Fetch the bug again
        bug = self.fetchBug(bugnum)

        bugModified = False

        # Mark bug as WORKSFORME if confirmed to no longer reproduce
        if closeBug:
          bugModified = True
          bug.status = "RESOLVED"
          bug.resolution = "WORKSFORME"

        # Mark bug as VERIFIED if we verified it successfully
        if verifyBug:
          bugModified = True
          bug.status = "VERIFIED"

        if whiteBoardModified:
          # We add "ignore" to our bugmon options so we don't update the bug a second time
          bugModified = True
          bug.whiteboard = " ".join(wbParts)
        
        try:
          if bugModified:
            bug.put()
          break
        except Exception as e:
          print "Caught exception: " + str(e)
          print traceback.format_exc()
          time.sleep(1)
        except:
          print "Failed to submit bug change, sleeping one second and retrying..."
          time.sleep(1)

      if (len(comments) > 0):
        comment = "\n".join(comments)
        print "Posting comment: "
        print comment
        print ""
        self.postComment(bugnum, comment)

    return

  def bisectBug(self, bugnum, reproductionResult, bisectForFix=False):
    # By default, bisect for the regressing changeset
    revFlag = '-e'
    if bisectForFix:
      revFlag = '-s'

    cmd = [ 'python', '/home/decoder/LangFuzz/fuzzing/autobisect-js/autoBisect.py', '-R', os.path.join(self.repoBase, reproductionResult.branchName), '-a', reproductionResult.arch, '-c', reproductionResult.ctype, revFlag, reproductionResult.origRev, '-p', " ".join(reproductionResult.testFlags) + " " + reproductionResult.testPath, '-i', 'crashes', '--timeout=10' ]
    outLines = subprocess.check_output(cmd).split("\n");
    retLines = []
    found = False
    for outLine in outLines:
      if not found and (outLine.find("autoBisect shows this is probably related") != -1 or outLine.find("Due to skipped revisions") != -1):
        found = True

      if found:
        # Remove possible email address
        if outLine.find("user:") != -1:
          outLine = re.sub("\s*<.+>", "", outLine)

        # autobisect emits a date at the end, skip that
        if (re.match("^\w+:", outLine) == None) and re.search("\s+\d{1,2}:\d{1,2}:\d{1,2}\s+", outLine) != None:
          continue

        retLines.append(outLine)

    return retLines

  def reproduceBug(self, bug, tipBranch=None):
    # Fetch the bug
    #bug = self.fetchBug(bugnum)
    bugnum = str(bug.id)

    # Determine comment to look at and revision
    testCommentIdx = 0
    rev = None

    if (bug.whiteboard != None):
      ret = re.compile('\[jsbugmon:([^\]]+)\]').search(bug.whiteboard)
      if (ret != None and ret.groups > 1):
        wbOpts = ret.group(1).split(",")
        for opt in wbOpts:
          if (opt.find("=") > 0):
            (cmd,param) = opt.split('=')
            if (cmd != None and param != None):
              if (cmd == "origRev"):
                rev = param
              elif (cmd == "testComment" and param.isdigit()):
                testCommentIdx = int(param)

    # Look for the first comment
    comment = bug.comments[testCommentIdx] if len(bug.comments) > testCommentIdx else None

    if (comment == None):
      raise BugException("Error: Specified bug does not have any comments")

    text = comment.text

    # Isolate revision to test for
    if (rev == None):
      rev = self.extractRevision(text)
    else:
      # Sanity check of the revision
      rev = self.extractRevision(rev)

    if (rev == None):
      raise BugException("Error: Failed to isolate original revision for test")

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
      raise BugException("Error: Unsupported architecture \"" + bug.platform + "\" required by bug")

    if (bug.version == "Trunk"):
      reponame = "mozilla-central"
    elif (bug.version == "Other Branch"):
      reponame = "ionmonkey"
    else:
      raise BugException("Error: Unsupported branch \"" + bug.version + "\" required by bug")

    if (tipBranch == None):
      tipBranch = reponame

    print "Repobase: " + self.repoBase
    print "Reponame: " + reponame
    repoDir = os.path.join(self.repoBase, reponame)
    tipRepoDir = os.path.join(self.repoBase, tipBranch)

    # We need at least some shell to extract the test from the bug, 
    # so we build a debug tip shell here already
    updated = False
    if not self.tipRev.has_key(repoDir):
      # If we don't know the tip revision for this branch, update and get it
      self.tipRev[repoDir] = self.hgUpdate(repoDir)
      updated = True
    (tipShell, tipRev) = self.getShell("cache/", arch, "dbg", 0, self.tipRev[repoDir], updated, repoDir)

    # If the file already exists, then we can reuse it
    if testCommentIdx > 0:
      testFile = "bug" + str(bugnum) + "-" + str(testCommentIdx) + ".js"
    else:
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
        # First try to find a suitable attachment
        attachments = [a for a in bug.attachments if not bool(int(a.is_obsolete))]
        for attachment in attachments:
          # Seriously, we don't need anything larger than 512kb here^^
          if (attachment.size <= 512*1024):
            # Refetch attachment with content
            url = urljoin(self.apiroot, 'attachment/%s/?%s&attachmentdata=1' % (attachment.id, self.bz.qs()))
            attachment = attachment.get(url)

            try:
              rawData = base64.b64decode(attachment.data)
              # Write our data to file
              outFile = open(testFile, "w")
              outFile.write(rawData)
              outFile.close()
              (err, ret) = testBinary(tipShell, testFile, [], 0, timeout=30)
              if (err.find("SyntaxError") < 0):
                # Found something that looks like JS :)
                found = True
                break
            except TypeError:
              pass

        # If we still haven't found any test, give up here...
        if not found:
          # Ensure we don't cache the wrong test
          os.remove(testFile)
          raise BugException("Error: Failed to isolate test from comment")

    (oouterr, oret) = (None, None)
    (origShell, origRev) = (None, None)

    # If we have an exact architecture, we will only test that
    if (archList == None):
      archList = [ arch ]

    for compileType in ['dbg', 'opt']:
      for archType in archList:
        # Update to tip and cache result:
        updated = False
        if not self.tipRev.has_key(tipRepoDir):
          # If we don't know the tip revision for this branch, update and get it
          self.tipRev[tipRepoDir] = self.hgUpdate(tipRepoDir)
          updated = True
      
        (tipShell, tipRev) = self.getShell("cache/", archType, compileType, 0, self.tipRev[tipRepoDir], updated, tipRepoDir)
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

        print ""

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
            return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, BugMonitorResult.statusCodes.REPRODUCED_TIP)
          else:
            print "Result: Bug still reproduces, but with different options: " + " ".join(tipOpts) # TODO need another code here in the future
            return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, BugMonitorResult.statusCodes.REPRODUCED_TIP)
        else:
          # Unlikely but possible, switched signal
          print "Result: Bug now reproduces with signal " + str(tret) + " (previously " + str(oret) + ")"
          return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, BugMonitorResult.statusCodes.REPRODUCED_SWITCHED)
      else:
        print "Result: Bug no longer reproduces"
        return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, BugMonitorResult.statusCodes.REPRODUCED_FIXED)
    else:
      print "Error: Failed to reproduce bug on original revision"
      return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, BugMonitorResult.statusCodes.FAILED)

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
