#!/usr/bin/python
import argparse
import FlawFndr
import sys

class Stynamic():
	flags = []
	def parseOpts(self):
		group0.add_argument('-v', metavar='verbose', action='store_true', help='Select verbose output')
		group0.add_argument('-q', metavar='quick', action='store_true', help='Select quiet output')
		group0.add_argument('-d', metavar='default', action='store_true', help='Select default output')

		group1 = parser.add_argument_group()
		group1.add_argument('-m', metavar='makefile', action='store', help='Specify makefile location to augment for running with Stynamic')
		group1.add_argument('-b', metavar='binary', action='store', help='Specify binary location for running with Stynamic')

		group2 = parser.add_mutually_exclusive_group()
		group2.add_argument('-a', action='store_true', required=False, help='Have Stynamic automatically determine source file list')
		group2.add_argument('-f', metavar='file', nargs='+', action='append',required=False,help='Specify files for Stynamic to check')
		flags = parser.parse_known_args(sys.argv[1:])
		print flags

	def instValgWrapper():
		#vl = ValWrap()
		#vl.setProg('./testFiles/ValTester')
		#vl.setArgs


	def instFlawfWrapper(self):
		ffargs = '-c'

		if (verbose):
			ffargs += '-n -m 0 --followdotdir'
		elif (quick):
			ffargs += '-F -m 4'
		else:	#default
			ffargs += '-m 1'

		if (makefile):
			

		fw = FlawFndr.FlawFinder()


def main():
	Styn = Stynamic()
	Styn.parseOpts()
	#Styn.instValgWrapper()
	#Styn.instFlawfWrapper()

if __name__ == '__main__': main()