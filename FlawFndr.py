#!/usr/bin/python3
import subprocess
import shlex
import re


class FlawFinder():
    """This class gives the ability to run flawfinder

    Uses import class subprocess and schlex

    Class Members:
        args -- the arguments (files) to give to run flawfinder
        outPut -- the output from running flawfinder
    """
    cFileFinder = re.compile(r"\w+.c")
    cHdrFinder = re.compile(r"\w+.h")
    cppFinder = re.compile(r"\w+.cpp")

    def __init__(self):
        self.args = None
        self.outPut = None
        self.errOuts = {}
        self.fileName = []
        self.errFnd = None

    def setArgs(self, Args):
        """Sets the arguments to pass into flawfinder

        Does not return anything

        Keyword Arguments:
            Args -- string that inludes the names of the files to run against
                    flawfinder
        """
        mainArg = 'flawfinder '
        mainArg += Args
        self.errFnd = re.compile("("+Args+"):(\d+):")
        cFiles = self.cFileFinder.findall(Args)
        hFiles = self.cHdrFinder.findall(Args)
        cppFiles = self.cppFinder.findall(Args)
        self.fileName.extend(cFiles)
        self.fileName.extend(hFiles)
        self.fileName.extend(cppFiles)
        self.args = shlex.split(mainArg)

    def runAnalysis(self):
        anlys = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        anlys.wait()
        tempOut = anlys.stdout.read()
        self.outPut = tempOut.decode('utf-8')
        self.outPut = self.outPut.replace('\n', ' ')

    def getOutPut(self):
        """Returns the output from running the analysis against a list of
        files
        """
        return self.outPut

    def parseOutput(self):
        endAnalys = re.compile(r'ANALYSIS SUMMARY:')
        anlys = endAnalys.search(self.outPut)
        frst = False
        pos = 0
        beg = self.errFnd.search(self.outPut)
        while(True):
            endEr = self.errFnd.search(self.outPut, beg.end())
            if endEr is not None:
                self.errOuts[
                    beg.group(2)] = self.outPut[
                    beg.end()+1:endEr.start()-1]
                beg = self.errFnd.search(self.outPut, endEr.end()+1)
                if not beg:
                    self.errOuts[endEr.group(2)] = self.outPut[endEr.end()+1:anlys.start()-1]
                    break
            else:
                self.errOuts[
                    beg.group(2)] = self.outPut[
                    beg.end()+1:anlys.start()-1]
                break

    def printErrors(self):
        for lineNum, err in self.errOuts.items():
            print('\nError at line number {}\n'.format(str(lineNum)))
            print(err)




def main():
    ff = FlawFinder()
    ff.setArgs('./testFiles/client.c')
    ff.runAnalysis()
    print('Before Parsing\n')
    print(ff.getOutPut())
    ff.parseOutput()
    print('\nAfter Parsing\n')
    ff.printErrors()


if __name__ == '__main__':main()
