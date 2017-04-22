#!/usr/bin/python
import argparse
import FlawFndr
import sys
from collections import defaultdict
from ValgWrapper import ValWrap


class Stynamic():
    flags = []
    valg_flags = []
    flaw_instn = []
    noFiles = False
    vl = ValWrap()
    fw = FlawFndr.FlawFinder()

    def parseOpts(self):
        parser = argparse.ArgumentParser(
            prog="Stynamic",
            description="Code vulnerability detection program that gets output from Static (from Flawfinder) and Dynamic (from Valgrind) code analysis of C++ code. Requires path to makefile or executeable code compiled with gcc using the -g flag for complete results.")
        group0 = parser.add_mutually_exclusive_group()
        group0.add_argument(
            '-q', action='store_true',
            help='Quiet level of output (Minimum) - exclusive from other output levels')
        group0.add_argument(
            '-d', action='store_true',
            help='Default level of output (Medium) - exclusive from other output levels')
        group0.add_argument(
            '-v', action='store_true',
            help='Verbose level of output (Maximum) - exclusive from other other levels')

        group1 = parser.add_argument_group()
        group1.add_argument(
            '-m', metavar='makefile', action='store',
            help='Specify makefile location to augment for running with Stynamic')
        group1.add_argument(
            '-b', metavar='binary', action='store',
            help='Specify binary location for running with Stynamic')

        group1.add_argument(
            '-ba', metavar='binary arguments', action='store', required=False,
            help='If binary requires arguments specify here')

        group2 = parser.add_mutually_exclusive_group()
        group2.add_argument(
            '-a', action='store_true', required=False,
            help='Have Stynamic automatically determine source file list')
        group2.add_argument(
            '-f',
            nargs='+',
            action='append',
            required=False,
            help='Specify files for Stynamic to check')
        self.flags = vars(parser.parse_known_args(sys.argv[1:])[0])
        self.valg_flags = parser.parse_known_args(sys.argv[1:])[1]
        if len(self.valg_flags) < 1:
            self.noFiles = True
        print(self.flags)
        print(self.valg_flags)

    def instValgWrapper(self):
#        if self.noFiles:
#            print('No files give, please rerun stynamic with a list of files.')
        print(self.flags['b'])
        self.vl.setProg(self.flags['b'])
        self.vl.setArgs(self.flags['ba'])

    def RunValg(self):
        #print('\nRunning analysis\n')
        #print('Memcheck-No tool Options')
#        self.vl.runAnlys('mem')
#        print('\nResults\n')
#        print(self.vl.getMemResults())
#        print('Memcheck- tool opt - Leak-Check=Full')
        self.vl.runAnlys('mem', {'lk_ch': 'full'})
#        print('\nResults\n')
#        print(self.vl.getMemResults())
#        print('Memcheck- tool opt - Leak-Check=Full with error flag True')
#        self.vl.runAnlys('mem', {'lk_ch': 'full'}, True)
#        print('\nResults\n')
        #print(self.vl.getMemResults())
        self.vl.parseOutput()

    def instFlawfWrapper(self):
        ffflags = '-c '
        ffargs = ''

        if (self.flags['v']):  # verbose level of output
            ffflags += '-n -m 0 --followdotdir '
        elif (self.flags['q']):  # quiet level of output
            ffflags += '-F -m 4 '
        else:  # default level of output - medium
            ffflags += '-m 1 '
        try:
            if (not self.flags['d']):
                ffargs += self.flags['f'][0][0]
            else:
                ffargs += './testFiles/ValTest.c'  # try to detect files in current directory
        except TypeError:
            sys.exit(
                'No files given to parse, please read the help menu and try again.')
        self.fw.setFlags(ffflags)
        self.fw.setArgs(ffargs)
        self.fw.runAnalysis()
        # print('\nBefore Parsing\n')
        # print(self.fw.getOutPut())
        self.fw.parseOutput()
        print('\nAfter Parsing\n')
       # self.fw.printErrors()
       # self.fw.printFnc()
       # self.fw.printFileNames()
        self.flaw_instn.append(self.fw)

    def prtyPrntOutBth(self):
        flawOut = {}
        valD = {}
        valOut = defaultdict(list)
        for flwIn in self.flaw_instn:
            flawOut[flwIn.getFileName()] = flwIn.getParsedErrors()

        print(self.vl.errorList)
        for valIn in self.vl.errorList:
            print('VAL OUTPUT!')
            print(valIn)
            k, w, l, f = valIn
            print(f)
            print(l + " " + w + " " + k)
            valD[l] = k + " : " + w
            valOut[f].append(valD)

        for fl, err in flawOut.items():
            print(fl + ' ')
            print(err)

        for fl, err in valOut.items():
            print(fl+ ' ')
            print(err)


def main():
    Styn = Stynamic()
    Styn.parseOpts()
    Styn.instValgWrapper()
    Styn.RunValg()
    Styn.instFlawfWrapper()
    Styn.prtyPrntOutBth()

if __name__ == '__main__':
    main()
