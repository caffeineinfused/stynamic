#!/usr/bin/python3

import os
import sys
import subprocess
import shlex


#Found this little cd trick from stackoverflow:
#http://stackoverflow.com/questions/431684/how-do-i-cd-in-python/13197763#13197763

class cd:
    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)



def auto_install():
    comm = ("sudo make prefix=/usr install")
    with cd("./dependencies/autoconf-2.69"):
        subprocess.call("./configure")
        subprocess.call("make")
        subprocess.call(shlex.split(comm))


def flaw_install():
    comm = ("make prefix=/usr install")
    with cd("./dependencies/flawfinder-1.31"):
        subprocess.call(shlex.split(comm))

def val_install():
    comm1 = ("./configure --prefix=/usr")
    comm2 = ("sudo make prefix=/usr install")
    with cd("./dependencies/valgrind-3.12.0"):
        subprocess.call("./autogen.sh")
        subprocess.call(shlex.split(comm1))
        subprocess.call("make")
        subprocess.call(shlex.split(comm2))

def depend_install():
    print("Installing dependencies")
    print("This may take a few minutes")
    auto_install()
    flaw_install()
    val_install()


def main():
    depend_install()

if __name__ == '__main__':
    main()
