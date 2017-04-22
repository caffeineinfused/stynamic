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
    cFileFinder = re.compile(r"\w+\.c")
    cHdrFinder = re.compile(r"\w+\.h")
    cppFinder = re.compile(r"\w+\.cpp")

    def __init__(self):
        self.args = 'flawfinder '
        self.noErrors = False
        self.noErrMsg = 'Congratulations no errors found by flawfinder'
        self.outPut = None
        self.errOuts = {}
        self.fileName = ""
        self.errFnd = None
        self.errFnc = {}
        self.flags = False

    def setFlags(self, flags):
        """Sets flags for flawfinder

        Returns nothing

        Keyword Arguments:
            flags -- a string consisting of flags for flawfinder
        """
        flgArg = self.args + flags
        self.flags = True
        self.args = flgArg

    def setArgs(self, Args):
        """Sets the arguments to pass into flawfinder

        Does not return anything

        Keyword Arguments:
            Args -- string that inludes the names of the files to run against
                    flawfinder
        """
        mainArg = ''
        if self.flags:
            mainArg = self.args + Args
        else:
            mainArg = 'flawfinder ' + Args
        print(mainArg)
        self.errFnd = re.compile("("+Args+"):(\d+):")
        cFiles = self.cFileFinder.search(Args)
        hFiles = self.cHdrFinder.search(Args)
        cppFiles = self.cppFinder.search(Args)
        if(cFiles != None):
            self.fileName = cFiles
        if(hFiles != None):
            self.fileName = hFiles
        if(cppFiles != None):
            self.fileName = cppFiles
        self.args = shlex.split(mainArg)

    def runAnalysis(self):
        anlys = subprocess.Popen(self.args, stdout=subprocess.PIPE)
        comm_tuple = anlys.communicate()
        self.outPut = comm_tuple[0].decode('utf-8')
        self.outPut = self.outPut.replace('\n', ' ')
        print("Analysis completed!")

    def getOutPut(self):
        """Returns the output from running the analysis against a list of
        files
        """
        return self.outPut

    def parseOutput(self):
        endAnalys = re.compile(r'ANALYSIS SUMMARY:')
        anlys = endAnalys.search(self.outPut)
        beg = self.errFnd.search(self.outPut)
        if not beg:
            self.noErrors = True
            return
        while(True):
            endEr = self.errFnd.search(self.outPut, beg.end())
            if endEr is not None:
                self.errOuts[
                    beg.group(2)] = self.outPut[
                    beg.end()+1:endEr.start()-1]
                beg = endEr
            else:
                self.errOuts[
                    beg.group(2)] = self.outPut[
                    beg.end()+1:anlys.start()-1]
                break

        self.parseBadFnctn()

    def parseBadFnctn(self):
        fncFndr = re.compile(r'(\w+):')
        for key, val in self.errOuts.items():
            fnc = fncFndr.search(val)
            if fnc is not None:
                self.errFnc[key] = fnc.group(1)

    def printErrors(self):
        # This function was the make sure the regex worked for finding error fnc
        if self.noErrors:
            print(self.noErrMsg)
        else:
            for lineNum, err in self.errOuts.items():
                print('\nError at line number {}\n'.format(str(lineNum)))
                print(err)

    def getParsedErrors(self):
        return self.errOuts

    def getFileName(self):
        return self.fileName

    def printFnc(self):
        # This function was to make sure the regex worked for finding file name
        if self.noErrors:
            print(self.noErrMsg)
        else:
            for line, fnc in self.errFnc.items():
                print('\nFunction {} error at line {}\n'.format(fnc, str(line)))

    def printFileNames(self):
        print('\n')
        print(self.fileName)


def main():
    ff = FlawFinder()
    ff.setArgs('/home/anthony/cyberproj/stynamic/dependencies/valgrind-3.12.0/memcheck/tests/str_tester.c')
    ff.runAnalysis()
    print('Before Parsing\n')
    print(ff.getOutPut())
    ff.parseOutput()
    print('\nAfter Parsing\n')
    ff.printErrors()
    ff.printFnc()
    ff.printFileNames()
if __name__ == '__main__':
    main()
