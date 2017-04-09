#!/usr/bin/python
import argparse
import sys
from ValgWrapper import ValWrap

class Stynamic():
	flags = []
	valg_flags = []
	vl = ValWrap()
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
		self.flags = vars(parser.parse_known_args(sys.argv[1:])[0])
		self.valg_flags = parser.parse_known_args(sys.argv[1:])[1]
		print self.flags
		print self.valg_flags
	def instValgWrapper(self):
		self.vl.setProg(self.flags['b'])
		self.vl.setArgs(self.valg_flags)
	def RunValg(self):
		    print('\nRunning analysis\n')
		    print('Memcheck-No tool Options')
		    self.vl.runAnlys('mem')
		    print('\nResults\n')
		    print(self.vl.getMemResults())
		    print('Memcheck- tool opt - Leak-Check=Full')
		    self.vl.runAnlys('mem', {'lk_ch':'full'})
		    print('\nResults\n')
		    print(self.vl.getMemResults())
		    print('Memcheck- tool opt - Leak-Check=Full with error flag True')
		    self.vl.runAnlys('mem', {'lk_ch':'full'}, True)
		    print('\nResults\n')
		    print(self.vl.getMemResults())

def main():
	Styn = Stynamic()
	Styn.parseOpts()
	Styn.instValgWrapper()
	Styn.RunValg()
if __name__ == '__main__': main()
