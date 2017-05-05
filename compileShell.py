#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import platform
import subprocess
import shutil
import sys
import re
import tempfile
import copy

from traceback import format_exc

path0 = os.path.dirname(__file__)
path1 = os.path.abspath(os.path.join(path0, os.pardir, 'util'))
sys.path.append(path1)
from subprocesses import captureStdout, macType, normExpUserPath, vdump
from countCpus import cpuCount

import signal

class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

# Run the testcase on the compiled js binary.
def testBinary(shell, file, flagsRequired, valgSupport, verbose=False, timeout=None):
    testBinaryCmd = [shell] + flagsRequired + [file]
    if valgSupport:
        valgPrefixCmd = []
        valgPrefixCmd.append('valgrind')
        if platform.system() == 'Darwin':
            valgPrefixCmd.append('--dsymutil=yes')
        valgPrefixCmd.append('--smc-check=all-non-file')
        valgPrefixCmd.append('--leak-check=full')
        testBinaryCmd = valgPrefixCmd + testBinaryCmd
    vdump('The testing command is:' + ' '.join(testBinaryCmd))

    # Capture stdout and stderr into the same string.
    p = subprocess.Popen(testBinaryCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (out,err) = ('', '')
    retCode = 0

    if (timeout != None):
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)  # 5 minutes
    try:
        out, err = p.communicate()
        signal.alarm(0)
        retCode = p.returncode
    except Alarm:
        p.terminate()

    if verbose:
        print 'The exit code is:', retCode
        if len(out) > 0:
            print 'stdout shows:', out
        if len(err) > 0:
            print 'stderr shows:', err

    # Switch to interactive input mode similar to `cat testcase.js | ./js -j -i`.
    # Doesn't work, stdout shows:
    #can't open : No such file or directory
    #The exit code is: 4
    #The second output is: None
    #if retCode == 0:
    #    # Append the quit() function to make the testcase quit.
    #    # Doesn't work if retCode is something other than 0, that watchExitCode specified.
    #    testcaseFile = open(file, 'a')
    #    testcaseFile.write('\nquit()\n')
    #    testcaseFile.close()
    #
    #    # Test interactive input.
    #    print 'Switching to interactive input mode in case passing as a CLI ' + \
    #            'argument does not reproduce the issue..'
    #    testBinaryCmd3 = subprocess.Popen([shell, methodJit, tracingJit, '-i'],
    #        stdin=(subprocess.Popen(['cat', file])).stdout)
    #    output2 = testBinaryCmd3.communicate()[0]
    #    retCode = testBinaryCmd3.returncode
    #    print 'The exit code is:', retCode
    #    print 'The second output is:', output2
    return out + "\n" + err, retCode

if __name__ == '__main__':
    pass
