#!/usr/bin/python
import argparse

class Stynamic():
	

	def parseOpts(self):
		parser = argparse.ArgumentParser(description = "Stynamic")
		group0 = parser.add_mutually_exclusive_group()
		group0.add_argument('-v', action='store_true')
		group0.add_argument('-q', action='store_true')
		group0.add_argument('-d', action='store_true')

		group1 = parser.add_argument_group()
		group1.add_argument('-m', metavar='makefile', action='store')
		group1.add_argument('-b', metavar='binary', action='store')

		group2 = parser.add_mutually_exclusive_group()
		group2.add_argument('-a', action='store_true', required=False)
		group2.add_argument('-f', metavar='files', nargs='+', action='append',required=False)
		parser.parse_known_args()

	#def instValgWrapper():

	#def setQuickFlags():

	#def setVerboseFlags():

def main():
	Styn = Stynamic()
	Styn.parseOpts()

if __name__ == '__main__': main()
