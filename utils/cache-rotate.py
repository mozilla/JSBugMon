import os
import sys
import shutil
from __builtin__ import file

def main():
    if len(sys.argv) < 2:
        print("Usage: %s <path to shell cache>" % sys.argv[0])
        sys.exit(1)
    
    path = sys.argv[1]

    while (getFreeSpacePercentage(path) < 0.05):
        shellDirs = os.listdir(path)
        
        (oldestShellDir, oldestShellDirAtime) = (None, None)
        
        for shellDir in shellDirs:
            binPath = None
            if shellDir.startswith("tboxjs-"):
                binPath = os.path.join(path, shellDir, "build", "dist", "js")
            elif shellDir.startswith("js-"):
                for file in os.listdir(os.path.join(path, shellDir)):
                    if file.startswith("js-"):
                        binPath = os.path.join(path, shellDir, file)
                        break
            else:
                continue
            
            if binPath:
                if not os.path.exists(binPath):
                    binPath = os.path.join(path, shellDir)

                if not oldestShellDirAtime or os.path.getatime(binPath) < oldestShellDirAtime:
                    oldestShellDir = os.path.join(path, shellDir)
                    oldestShellDirAtime = os.path.getatime(binPath)
        
        if oldestShellDir:
            shutil.rmtree(oldestShellDir)
        
def getFreeSpacePercentage(path):
    statvfs = os.statvfs(path)
    pfree = (statvfs.f_bavail * statvfs.f_frsize) / float((statvfs.f_blocks * statvfs.f_frsize))
    return pfree
    
if __name__ == "__main__":
    sys.exit(main())
