#!/usr/bin/python
import argparse
import sys

class Stynamic():
	flags = []
	def parseOpts(self):
		parser = argparse.ArgumentParser(description = "Stynamic")
		group0 = parser.add_mutually_exclusive_group()
		group0.add_argument('-v', action='store_true', help='Select verbose output')
		group0.add_argument('-q', action='store_true', help='Select quiet output')
		group0.add_argument('-d', action='store_true', help='Select default output')

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
def main():
	Styn = Stynamic()
	Styn.parseOpts()
	#Styn.instValgWrapper()

if __name__ == '__main__': main()
