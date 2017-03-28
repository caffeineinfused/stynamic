#!/usr/bin/python
from subprocess import *

class FlawWrapper(object):
	out = ""
	ff_args = []
	ff_binary = "flawfinder"
	
	def __init__(self):
		self.ff_args.append(self.ff_binary)
		
		
	def add_arg(self, arg, arg_val):
		self.ff_args.append(arg)
		self.ff_args.append(arg_val)

	def add_arg(self, arg):
		self.ff_args.append(arg)

	def launch(self):
		ff_run_args = []
		for arg in self.ff_args:
			ff_run_args.append(arg)
		print ff_run_args
		p = Popen(ff_run_args, shell=False, stdin=None, stdout=PIPE, stderr=STDOUT, close_fds=True)
		self.out = p.stdout.read()
	
	def get_out(self):
		return self.out

ff = FlawWrapper()
ff.add_arg("--help")
ff.launch()
print ff.get_out()
