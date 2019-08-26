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
import sys

from optparse import OptionParser

from compileShell import testBinary
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


    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.error('Not enough arguments')
  
    return (options, args)

def main():
    # Script options
    (options, args) = parseOpts()

    # Get the API root, default to bugzilla.mozilla.org
    API_ROOT = os.environ.get('BZ_API_ROOT',
                              'https://bugzilla.mozilla.org/bzapi/')

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
        print traceback.format_exc()
      except Exception as e:
        print "Caught exception: " + str(e)
        print traceback.format_exc()


class BugException(Exception):
  pass

class InternalException(Exception):
  pass

class BugMonitorResult:
  # Different result states:
  #  FAILED               - Unable to reproduce on original revision
  #  REPRODUCED_FIXED     - Reproduced on original revision but not on tip (fixed on tip)
  #  REPRODUCED_TIP       - Reproduced on both revisions
  #  REPRODUCED_SWITCHED  - Reproduced on tip, but with a different crash/signal
  statusCodes = enum('FAILED', 'REPRODUCED_FIXED', 'REPRODUCED_TIP', 'REPRODUCED_SWITCHED')

  def __init__(self, branchName, origRev, tipRev, testFlags, testPath, arch, ctype, buildFlags, status):
    self.branchName = branchName
    self.origRev = origRev
    self.tipRev = tipRev
    self.testFlags = testFlags
    self.testPath = testPath
    self.arch = arch
    self.ctype = ctype
    self.buildFlags = buildFlags
    self.status = status

class BugMonitor:

  def __init__(self, apiroot, username, password, repoBase, options):
    self.apiroot = apiroot
    self.bz = BugzillaAgent(apiroot, username, password)
    
    self.repoBase = repoBase

    # Here we store the tip revision per repository for caching purposes
    self.tipRev = {}

    self.allowedOpts = [ 
        '--fuzzing-safe',
        '--ion-eager',
        '--baseline-eager',
        '--ion-regalloc=backtracking',
        '--ion-regalloc=lsra',
        '--thread-count=2',
        '--ion-parallel-compile=off',
        '--ion-offthread-compile=off',
        '--ion-check-range-analysis',
        '--ion-gvn=pessimistic',
        '--ion-gvn=off',
        '--no-ion',
        '--no-baseline',
        '--arm-sim-icache-checks',
        '--arm-asm-nop-fill=1',
        '--no-threads',
        '--unboxed-objects',
	'--ion-fuzzer-checks',
	'--ion-extra-checks',
        '--arm-hwcap=vfp',
        '--ion-shared-stubs=on',
        '--ion-pgo=on',
        '-D'
    ]

    with open(os.path.join(repoBase, 'mozilla-central', 'config', 'milestone.txt'), 'rb') as fh:
      self.centralVersion = fh.readlines()[-1]

    self.centralVersion = int(self.centralVersion.split('.', 1)[0])

    self.branches = ['mozilla-central', 'mozilla-aurora', 'mozilla-beta', 'mozilla-release']

    # Misc options
    self.options = options

  def fetchBug(self, bug_id):
    bug = self.bz.get_bug(bug_id)
    if bug.depends_on != None and len(bug.depends_on) > 0:
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

    bugModified = False
    bugVerified = False
    verifiedFlags = []
    comments = []

    if (bug.status == "RESOLVED" and bug.resolution == "FIXED"):
      result = self.reproduceBug(bug)

      if (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
        if updateBug:
          print "Marking bug " + str(bugnum) + " as verified fixed..."
          # Mark VERIFIED FIXED now
          bugVerified = True
          bugModified = True

          # Add a comment
          comments.append("JSBugMon: This bug has been automatically verified fixed.")
        else:
          print "Would mark bug " + str(bugnum) + " as verified fixed..."

    for branchNum in range(self.centralVersion - 3, self.centralVersion):
      statusFlagName = 'cf_status_firefox' + str(branchNum)

      if (bug.api_data[statusFlagName] == 'fixed'):
        branchRepo = self.branches[self.centralVersion - branchNum]
        branchRepoRev = self.hgFindFixParent(os.path.join(self.repoBase, branchRepo), bugnum)

        if branchRepoRev == None:
          print "Unable to find fix parent for bug %s on repository %s" % (str(bugnum), branchRepo)
          continue

        result = self.reproduceBug(bug, branchRepo, branchRepoRev)

        if (result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
          if updateBug:
            print "Marking bug " + str(bugnum) + " as verified fixed on Fx" + str(branchNum) + " ..."
            verifiedFlags.append(statusFlagName)
            bugModified = True
            comments.append("JSBugMon: This bug has been automatically verified fixed on Fx" + str(branchNum))
          else:
            print "Would mark bug " + str(bugnum) + " as verified fixed on Fx" + str(branchNum) + " ..."

    if bugModified:
      while True:
        for flag in verifiedFlags:
          bug.api_data[flag] = 'verified'

        if bugVerified:
          bug.status = "VERIFIED"
          bug.api_data['cf_status_firefox' + str(self.centralVersion)] = 'verified'

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

    if len(comments) > 0:
      comment = "\n".join(comments)
      print "Commenting: "
      print comment
      self.postComment(bugnum, comment)

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
    bugBisectForceCompile = False
    bugFailureMsg = None
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

      if ('bisect-force-compile' in wbOpts):
        bugBisectForceCompile = True

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
                if not branch in self.branches:
                  continue
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
            try:
              result = self.reproduceBug(bug)
            except BugException as b:
              bugFailureMsg = "JSBugMon: Cannot process bug: " + str(b)
            except InternalException:
              # Propagate internal failures, don't update the bug
              raise
            except Exception as e:
              bugFailureMsg = "JSBugMon: Cannot process bug: Unknown exception (check manually)"
              print "Caught exception: " + str(e)
              print traceback.format_exc()

          if result != None:
            if (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP or result.status == BugMonitorResult.statusCodes.REPRODUCED_SWITCHED):
              bugReproduced = True
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

            elif (result.status == BugMonitorResult.statusCodes.FAILED):
              bugFailureMsg = "JSBugMon: Cannot process bug: Unable to automatically reproduce, please track manually."
              

      # If we already failed with the update command, don't try to bisect for now
      if bugFailureMsg != None:
        bugBisectRequested = False
        bugBisectFixRequested = False

      if bugBisectRequested and bug.status != "RESOLVED" and bug.status != "VERIFIED":
        if result == None:
          try:
            result = self.reproduceBug(bug)
          except BugException as b:
            bisectComments.append("JSBugMon: Bisection requested, failed due to error: " + str(b))
            bisectComments.append("")
        if (result != None and (result.status == BugMonitorResult.statusCodes.REPRODUCED_TIP or result.status == BugMonitorResult.statusCodes.REPRODUCED_SWITCHED or result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED)):
          print "Bisecting bug " +  str(bugnum) + " ..."
          bisectComment = self.bisectBug(bugnum, result, forceCompile=bugBisectForceCompile)
          if bisectComment != None:
            print bisectComment
            if len(bisectComment) > 0:
              bisectComments.append("JSBugMon: Bisection requested, result:")
              bisectComments.extend(bisectComment)
            else:
              bisectComments.append("JSBugMon: Bisection requested, failed due to error (try manually).")
              bisectComments.append("");
          else:
            # Threat this as a temporary failure, don't remove the whiteboard tag
            bugBisectRequested = False

      if bugBisectFixRequested:
        if result == None:
          try:
            result = self.reproduceBug(bug)
          except BugException as b:
            bisectComments.append("JSBugMon: Fix Bisection requested, failed due to error: " + str(b))
            bisectComments.append("")
        if (result != None and result.status == BugMonitorResult.statusCodes.REPRODUCED_FIXED):
          print "Bisecting fix for bug " +  str(bugnum) + " ..."
          bisectComment = self.bisectBug(bugnum, result, bisectForFix=True, forceCompile=bugBisectForceCompile)
          if bisectComment != None:
            print bisectComment
            if len(bisectComment) > 0:
              bisectFixComments.append("JSBugMon: Fix Bisection requested, result:")
              bisectFixComments.extend(bisectComment)
            else:
              bisectFixComments.append("JSBugMon: Fix Bisection requested, failed due to error (try manually).")
              bisectFixComments.append("");
          else:
            # Threat this as a temporary failure, don't remove the whiteboard tag
            bugBisectFixRequested = False

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

      if ((bugBisectRequested or (bugBisectFixRequested and len(bisectFixComments) > 0)) and bugBisectForceCompile):
        whiteBoardModified = True
        wbOpts.remove('bisect-force-compile')
        
      if bugFailureMsg != None and bugUpdateRequested:
        whiteBoardModified = True
        wbOpts.remove('update')
        comments.append(bugFailureMsg)

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

  def bisectBug(self, bugnum, reproductionResult, bisectForFix=False, forceCompile=False):
    if forceCompile:
      return self.bisectBugCompile(bugnum, reproductionResult, bisectForFix)

    buildOpts = '-R %s' % (os.path.join(self.repoBase, reproductionResult.branchName))
    if reproductionResult.buildFlags != None and len(reproductionResult.buildFlags) > 0:
        buildOpts += ' %s' % " ".join(reproductionResult.buildFlags)

    cmd = [ 'python', '/srv/repos/funfuzz/autobisect-js/autoBisect.py', '-T', '-b', buildOpts, '-p', " ".join(reproductionResult.testFlags) + " " + reproductionResult.testPath, '-i', 'crashes', '--timeout=10' ]
    print "DEBUG: Attempting binary bisection: %s" % str(cmd)
    outLines = None
    try:
      outLines = subprocess.check_output(cmd).split("\n");
    except subprocess.CalledProcessError:
      # Threat this as a temporary failure, fallback to compiled bisection
      return self.bisectBugCompile(bugnum, reproductionResult, bisectForFix)

    retLines = []
    found = False
    for outLine in outLines:
      if not found and (outLine.find("Build Bisection Results by autoBisect ===") != -1):
        found = True

      if found:
        retLines.append(outLine)

    if not found:
	# Binary bisection failed for some reason, fallback to compiled bisection
    	return self.bisectBugCompile(bugnum, reproductionResult, bisectForFix)

    return retLines

  def bisectBugCompile(self, bugnum, reproductionResult, bisectForFix=False):
    # By default, bisect for the regressing changeset
    revFlag = '-e'
    if bisectForFix:
      revFlag = '-s'

    buildOpts = '-R %s' % (os.path.join(self.repoBase, reproductionResult.branchName))
    if reproductionResult.buildFlags != None and len(reproductionResult.buildFlags) > 0:
        buildOpts += ' %s' % " ".join(reproductionResult.buildFlags)

    cmd = [ 'python', '/srv/repos/funfuzz/autobisect-js/autoBisect.py', '-b', buildOpts, revFlag, reproductionResult.origRev, '-p', " ".join(reproductionResult.testFlags) + " " + reproductionResult.testPath, '-i', 'crashes', '--timeout=10' ]
    print "DEBUG: %s" % str(cmd)
    outLines = None
    try:
      outLines = subprocess.check_output(cmd).split("\n");
    except subprocess.CalledProcessError:
      # Threat this as a temporary failure
      return None

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

  def reproduceBug(self, bug, tipBranch=None, tipBranchRev=None):
    bugnum = str(bug.id)

    # Determine comment to look at and revision
    testCommentIdx = 0
    rev = None

    if (tipBranch != None and tipBranchRev != None):
        rev = tipBranchRev

    if (bug.whiteboard != None):
      ret = re.compile('\[jsbugmon:([^\]]+)\]').search(bug.whiteboard)
      if (ret != None and ret.groups > 1):
        wbOpts = ret.group(1).split(",")
        for opt in wbOpts:
          if (opt.find("=") > 0):
            (cmd,param) = opt.split('=')
            if (cmd != None and param != None):
              if (cmd == "origRev" and rev == None):
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


    buildFlags = []

    checkFlags = ["--enable-more-deterministic", "--enable-simulator=arm", "--enable-arm-simulator", "--enable-debug", "--disable-debug", "--enable-optimize", "--disable-optimize"]

    for flag in checkFlags:
      if (re.search(flag + "[^-a-zA-Z0-9]", text) != None):
        buildFlags.append(flag)

    # Flags to use when searching for the test ("scanning") using SyntaxError method
    scanOpts = ['--fuzzing-safe']
    viableOptsList = []
    opts = []

    for opt in self.allowedOpts:
      if (text.find(opt) != -1):
        opts.append(opt)

    viableOptsList.append(opts)

    print "Extracted options: %s" % (' '.join(opts))

    # Special hack for flags that changed
    if "--ion-parallel-compile=off" in opts:
      optsCopy = []
      for opt in opts:
        if opt == "--ion-parallel-compile=off":
          optsCopy.append("--ion-offthread-compile=off")
        else:
          optsCopy.append(opt)
      viableOptsList.append(optsCopy)
    
    if (bug.version == "Trunk"):
      reponame = "mozilla-central"
    elif (bug.version == "Other Branch"):
      reponame = "ionmonkey"
    else:
      raise BugException("Error: Unsupported branch \"" + bug.version + "\" required by bug")

    # Default to using the bug.version field as repository specifier
    repoDir = os.path.join(self.repoBase, reponame)

    # If told to use a different tipBranch, use that for tip testing
    if (tipBranch == None):
      tipBranch = reponame

    tipRepoDir = os.path.join(self.repoBase, tipBranch)

    # If we are given a specific revision even for testing, then use
    # the tipBranch for all testing, including initial reproduction
    if (tipBranchRev != None):
      repoDir = tipRepoDir

    print "Using repository at %s with revision %s for initial reproduction" % (repoDir, rev)
    print "Using repository at %s with tip revision for testing" % (tipRepoDir)

    arch = None
    archList = None
    if (bug.platform == "x86_64"):
      arch = "64"
    elif (bug.platform == "x86"):
      arch = "32"
    elif (bug.platform == "All"):
      arch = "64"
      archList = [ "64", "32" ] # TODO: Detect native platform here
      
      # When auto-detecting, avoid using ARM simulator for now
      if "--enable-simulator=arm" in buildFlags:
        buildFlags.remove("--enable-simulator=arm")
    elif (bug.platform == "ARM"):
      arch = "32"
      buildFlags.append("--enable-simulator=arm")
    else:
      raise BugException("Error: Unsupported architecture \"" + bug.platform + "\" required by bug")

    # We need at least some shell to extract the test from the bug, 
    # so we build a debug shell here already
    try:
      (testShell, testRev) = self.getShell("cache/", arch, "dbg", 0, rev, False, repoDir, buildFlags)
    except Exception:
      trace = sys.exc_info()[2]
      raise InternalException("Failed to compile tip shell (toolchain broken?)"), None, trace

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
        print "Testing syntax with shell %s" % testShell
        (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)

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
              (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)
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
              (err, ret) = testBinary(testShell, testFile, scanOpts, 0, timeout=30)
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
        try:
          (origShell, origRev) = self.getShell("cache/", archType, compileType, 0, rev, False, repoDir, buildFlags)
        except Exception:
          # Unlike compilation failures on tip, we must not ignore compilation failures with the original
          # revision, as it could mean that the bug was filed with a broken revision.
          raise BugException("Error: Failed to compile specified revision %s (maybe try another?)" % rev)

        for opts in viableOptsList:
          (oouterr, oret) = testBinary(origShell, testFile, opts , 0, verbose=self.options.verbose, timeout=30)
          if (oret < 0):
            break

        # If we reproduced with one arch, then we don't need to try the others
        if (oret < 0):
          break

        print ""

      # If we reproduced with dbg, then we don't need to try opt
      if (oret < 0):
        break

    # Check if we reproduced at all (dbg or opt)
    if (oret < 0):
      print ""
      print "Successfully reproduced bug (exit code " + str(oret) + ") on original revision " + rev + ":"
      errl = oouterr.split("\n")
      if len(errl) > 2: errl = errl[-2:]
      for err in errl:
        print err

      # Try running on tip now
      print "Testing bug on tip..."

      # Update to tip and cache result:
      updated = False
      if not self.tipRev.has_key(tipRepoDir):
        # If we don't know the tip revision for this branch, update and get it
        self.tipRev[tipRepoDir] = self.hgUpdate(tipRepoDir)
        updated = True
      
      try:
        (tipShell, tipRev) = self.getShell("cache/", archType, compileType, 0, self.tipRev[tipRepoDir], updated, tipRepoDir, buildFlags)
      except Exception:
        trace = sys.exc_info()[2]
        raise InternalException("Failed to compile tip shell (toolchain broken?)"), None, trace

      tipOpts = None
      for opts in viableOptsList:
        (touterr, tret) = testBinary(tipShell, testFile, opts , 0, verbose=self.options.verbose, timeout=30)
        if (tret < 0):
          tipOpts = opts
          break

      if (tret < 0):
        if (tret == oret):
          if (opts == tipOpts):
            print "Result: Bug still reproduces"
            return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.REPRODUCED_TIP)
          else:
            print "Result: Bug still reproduces, but with different options: " + " ".join(tipOpts) # TODO need another code here in the future
            return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.REPRODUCED_TIP)
        else:
          # Unlikely but possible, switched signal
          print "Result: Bug now reproduces with signal " + str(tret) + " (previously " + str(oret) + ")"
          return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.REPRODUCED_SWITCHED)
      else:
        print "Result: Bug no longer reproduces"
        return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.REPRODUCED_FIXED)
    else:
      print "Error: Failed to reproduce bug on original revision"
      #return BugMonitorResult(reponame, rev, self.tipRev[tipRepoDir], opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.FAILED)
      return BugMonitorResult(reponame, rev, None, opts, testFile, archType, compileType, buildFlags, BugMonitorResult.statusCodes.FAILED)

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

  def hgFindFixParent(self, repoDir, bugNum):
    prevRev = None
    hgOut = captureStdout(['hg', 'log', '-l', '10000', '--template', '{node} {desc}\n'], ignoreStderr=True, currWorkingDir=repoDir)[0].split("\n")
    for line in reversed(hgOut):
      line = line.split(' ', 1)

      if len(line) < 2:
        continue

      rev = line[0][0:12]

      if (line[1].find(str(bugNum)) != -1):
        return prevRev

      prevRev = rev
    return None

  def hgUpdate(self, repoDir, rev=None):
      try:
          print "Running hg update..."
          if (rev != None):
              captureStdout(['hg', 'update', '-C', '-r', rev], ignoreStderr=True, currWorkingDir=repoDir)
          else:
              captureStdout(['hg', 'update', '-C'], ignoreStderr=True, currWorkingDir=repoDir)

          hgIdCmdList = ['hg', 'identify', repoDir]
          # In Windows, this throws up a warning about failing to set color mode to win32.
          if platform.system() == 'Windows':
              hgIdFull = captureStdout(hgIdCmdList, currWorkingDir=repoDir, ignoreStderr=True)[0]
          else:
              hgIdFull = captureStdout(hgIdCmdList, currWorkingDir=repoDir)[0]
          hgIdChangesetHash = hgIdFull.split(' ')[0]

          #os.chdir(savedPath)
          return hgIdChangesetHash
      except:
	  print "Unexpected error while updating HG:", sys.exc_info()[0]
	  sys.exit(1)

  def getShell(self, shellCacheDir, archNum, compileType, valgrindSupport, rev, updated, repoDir, buildFlags=None):
    shell = None

    # This code maps the old "-c dbg / -c opt" configurations to their configurations
    haveDebugOptFlags = False

    if buildFlags != None:
      haveDebugOptFlags = ('--enable-debug' in buildFlags) or ('--disable-debug' in buildFlags) or ('--enable-optimize' in buildFlags) or ('--disable-optimize' in buildFlags)

    print "haveDebugOptFlags: %s %s" % (str(haveDebugOptFlags), " ".join(buildFlags))

    if compileType == 'dbg':
      if buildFlags != None:
        if not haveDebugOptFlags:
          buildFlags.append('--enable-debug')
          buildFlags.append('--enable-optimize')
      else:
        buildFlags = [ '--enable-debug', '--enable-optimize' ]
    elif compileType == 'opt':
      if buildFlags != None:
        if not haveDebugOptFlags:
          buildFlags.append('--disable-debug')
          buildFlags.append('--enable-optimize')
      else:
        buildFlags = [ '--disable-debug', '--enable-optimize' ]

    if archNum == "32":
        buildFlags.append('--32')

    buildOpts = '-R %s' % (repoDir)
    if buildFlags != None and len(buildFlags) > 0:
        buildOpts += ' %s' % " ".join(buildFlags)

    if (shell == None):
      if (rev == None):
        rev = self.hgUpdate(repoDir, rev)
        print "Compiling a new shell for tip (revision " + rev + ")"
      else:
        print "Compiling a new shell for revision " + rev
      shell = captureStdout(['/srv/repos/funfuzz/js/compileShell.py', '-b', buildOpts, '-r', rev])[0].split("\n")[-1]

    return (shell, rev)

if __name__ == '__main__':
    main()
