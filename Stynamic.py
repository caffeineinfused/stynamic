#!/usr/bin/python3
import argparse
import FlawFndr
import sys
import textwrap
from collections import defaultdict
import os, fnmatch
from ValgWrapper import ValWrap
from itertools import zip_longest


class Stynamic():
    flags = []
    flaw_instn = []
    noFiles = False
    vl = ValWrap()
    fw = FlawFndr.FlawFinder()
    #start borrowed method
    def find(self, pattern, path): #entire method taken from StackOverflow: https://stackoverflow.com/questions/1724693/find-a-file-in-python
        result = []
        for root, dirs, files in os.walk(path):
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    result.append(os.path.join(root, name))
        return result
    #end borrowed method


    def parseOpts(self):
        parser = argparse.ArgumentParser(
            prog="Stynamic",
            description="Code vulnerability detection program that gets output from Static (from Flawfinder) and Dynamic (from Valgrind) code analysis of C++ code. Requires executeable code compiled with gcc using the -g flag for complete results.")
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
            '-b', metavar='binary', action='append',
            help='Specify binary location for running with Stynamic')


        group1.add_argument(
            '-ba', metavar='binary arguments', action='append', required=False,
            help='If binary requires arguments specify here')

        group2 = parser.add_argument_group()

        group2.add_argument(
            '-a',
            required=False,
            action='append',
            nargs='*',
            metavar='pattern',
            help='Have Stynamic automatically determine source file list from the provided pattern(s)')
        group2.add_argument(
            '-f',
            nargs='*',
            action='append',
            required=False,
            metavar='file',
            help='Specify file(s) for Stynamic to check')
        self.flags = vars(parser.parse_args(sys.argv[1:]))
        #print(self.flags)
        return parser

    def instValgWrapper(self):

        #print(self.flags['b'][0])
        self.vl.setProg(self.flags['b'][0])
        if(self.flags['ba'] != None):
            self.vl.setArgs(self.flags['ba'][0])

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

    def flawFileList(self):
        list = []
        try:
            for filelist in self.flags['f']:
                for file in filelist:
                    list.append(file)
                    #print "file:" + file + "\n"
        except TypeError:
            print('')

        try:
            for regexlist in self.flags['a']:
                #print "regexlist:" + str(regexlist) + "\n"
                for regex in regexlist:
                    #print "regex:" + regex + "\n"
                    for file in self.find(regex, os.getcwd()):
                        list.append(file)
                        #print "file2:" + file + "\n"
        except TypeError:
            print('')
        #print list
        return list

    def instFlawfWrapper(self, file):
        ffflags = '-c '
        ffargs = file

        if (self.flags['v']):  # verbose level of output
            ffflags += '-n -m 0 --followdotdir '
        elif (self.flags['q']):  # quiet level of output
            ffflags += '-F -m 4 '
        else:  # default level of output - medium
            ffflags += '-m 1 '
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
        fileSet = set()
        flawOut = {}
        valD = defaultdict(list)
        valOut = {}
        for flwIn in self.flaw_instn:
            fName = flwIn.getFileName()
            flawOut[fName.group(0)] = flwIn.getParsedErrors()
            fileSet.add(fName.group(0))

        print(self.vl.errorList)
        for valIn in self.vl.errorList:
            k = valIn.kind
            f = valIn.file
            w = valIn.what
            l = valIn.line
            valD[l].append(k + " : " + w)
            valOut[f] = valD
            fileSet.add(f)

        sttc = "Static Analysis"
        dyn = "Dynamic Analysis"
        #for fk, vk in zip_longest(flawOut.keys(), valOut.keys(), fillvalue=''):
        #print("*"*97)
        #print("| {0:^45} | {1:^45} |".format(sttc.center(40), dyn.center(40)))
        res = "Results!"
        print("*"*97)
        print("| {0:93} |".format(res.center(93)))
        for fl in fileSet:
            print("*"*97)
            vO = {}
            fO = {}
            if fl in valOut:
                vO = valOut[fl]
            if fl in flawOut:
                fO = flawOut[fl]

            if not vO:
                print("-"*97)
                print('\nFile name: '+fl);
                print("-"*97)
                print("| {0:^45} | {1:^45} |".format(sttc.center(40), dyn.center(40)))
                print("*"*97)
                for line, error in sorted(fO.items()):
                    outP = 'Line: '+line+'\t\tError: '+error
                    output = textwrap.wrap(outP, width=40, replace_whitespace=False)
                    blnk = " "
                    for out in output:
                        print("| {0:<45} | {1:>45} |".format(out.center(40), blnk))
                    print("|"+" "*47+"|"+" "*47+"|")
                continue

            if not fO:
                print("-"*97)
                print('\nFile name: '+fl);
                print("-"*97)
                print("| {0:^45} | {1:^45} |".format(sttc.center(40), dyn.center(40)))
                print("*"*97)
                for line, error in sorted(vO.items()):
                    outP = "Line: "+line+"\t\tError: "+error
                    output = textwrap.wrap(outP, width=40, replace_whitespace=False)
                    blnk = " "
                    for out in output:
                        print("| {0:<45} | {1:>45} |".format(out.center(40), blnk))
                    print("|"+" "*47+"|"+" "*47+"|")
                continue

            print("-"*97)
            print("\nFile Name: "+fl)
            print("-"*97)
            print("| {0:^45} | {1:^45} |".format(sttc.center(40), dyn.center(40)))
            print("*"*97)
            for x, y in sorted(zip_longest(fO.keys(), vO.keys(), fillvalue='-')):
                if x in fO and y in vO:
                    valStrng = 'Line: '+ y+'\t\tError: '
                    for ln in vO[y]:
                        valStrng += ln + '\t\t\t'
                    fL = 'Line: '+x+'\t\tError: '+fO[x] + '\n'
                    fL = textwrap.wrap(fL, width=40, replace_whitespace=False)
                    vL = textwrap.wrap(valStrng, width=40, replace_whitespace=False)
                    for f, v in zip_longest(fL, vL, fillvalue=' '):
                        print('| {0:<45} | {1:>45} |'.format(f.center(40), v.center(40)))
                    print("|"+" "*47+"|"+" "*47+"|")
                    continue

                elif x in fO:
                    fL = 'Line: '+x+'\t\tError: '+fO[x] + '\n'
                    fL = textwrap.wrap(fL, width=40, replace_whitespace=False)
                    bnk = " "
                    for outp in fL:
                        print('| {0:<45} | {1:>45} |'.format(outp.center(40), bnk.center(40)))
                    print("|"+" "*47+"|"+" "*47+"|")
                    continue

                else:
                    fL = 'Line: '+x+'\t\tError: '
                    for ln in vO[y]:
                        fL += ln + '\t\t\t'
                    fL = textwrap.wrap(fL, width=40, replace_whitespace=False)
                    bnk = " "
                    for outp in fL:
                        print('| {0:<45} | {1:>45} |'.format(outp.center(40), bnk.center(40)))
                    print("|"+" "*47+"|"+" "*47+"|")
                    continue

def main():
    Styn = Stynamic()
    parser = Styn.parseOpts()
    skip=False
    if(Styn.flags['b'] == None and not(Styn.flags['a'] != None or Styn.flags['f'] != None)):
        parser.print_help()

    if(Styn.flags['ba'] != None and len(Styn.flags['ba']) > 1):
        print("Only one set of binary arguments may be specified\n")
        parser.print_help()
        skip = True

    if(Styn.flags['b'] != None and len(Styn.flags['b']) == 1 and not skip):
        Styn.instValgWrapper()
        Styn.RunValg()
    elif(Styn.flags['b'] != None and len(Styn.flags['b']) > 1):
        print("Only one binary may be specified\n")
        parser.print_help()

    if(Styn.flags['a'] != None or Styn.flags['f'] != None and not skip):
        list = Styn.flawFileList()
        for file in list:
            Styn.fw = FlawFndr.FlawFinder()
            Styn.instFlawfWrapper(file)
        Styn.prtyPrntOutBth()

if __name__ == '__main__':
    main()
