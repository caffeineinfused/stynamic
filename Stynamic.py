#!/usr/bin/python
import argparse
import FlawFndr

class Stynamic():
	

	def parseOpts(self):
		parser = argparse.ArgumentParser(description = "Stynamic")
		group0 = parser.add_mutually_exclusive_group()
		group0.add_argument('-v', metavar='verbose', action='store_true', help='verbose output, exclusive from -q')
		group0.add_argument('-q', metavar='quick', action='store_true', help='quick output, exclusive from -v')
		group0.add_argument('-d', action='store_true')

		group1 = parser.add_argument_group()
		group1.add_argument('-m', metavar='makefile', action='store', help='path to makefile')
		group1.add_argument('-b', metavar='binary', action='store', help='path to binary')

		group2 = parser.add_mutually_exclusive_group()
		group2.add_argument('-a', action='store_true', help='auto file list, exclusive from -f, proposes file list', required=False)
		group2.add_argument('-f', metavar='files', nargs='+', action='append', help='file list (can be taken multiple times)', required=False)
		parser.parse_known_args()

	#def instValgWrapper():

	#def setQuickFlags():

	#def setVerboseFlags():

	def setFFVerboseFlags(self):
		return '-n -m 0 --followdotdir'

	def setFFQuickFlags(self):
		return '-F -m 4'

	def setFFDefaultFlags(self):
		return ''

	def instFlawfWrapper(self):
		ffargs = '-c'

		if (verbose):
			ffargs += setFFVerboseFlags()
		elif (quick):
			ffargs += setFFQuickFlags()
		else:

		fw = FlawFndr.FlawFinder()


def main():
	Styn = Stynamic()
	Styn.parseOpts()
	Styn.instFlawfWrapper()

if __name__ == '__main__': main()
