#!/usr/bin/python3
import re
import subprocess
import shlex
import xml.etree.ElementTree as ET    
mem_opts = {  # Options in comments
    'lk_ch': '--leak-check=',  # no|summary|yes|fill def-Sum
    'lk_res': '--leak-resolution=',  # low|med|high def-high
    'sh_lk': '--show-leak-kinds=',  # <set> def-definite,possible
    'er_lk': '--errors-for-leak-kinds=',  # <set> def-all
    'lk_hr': '--leak-check-heuristics=',  # <set> def-all
    'sh_re': '--show-reachable=',  # yes|no
    'sh_pLst': '--show-possibly-lost=',  # yes|no
    'und_er': '--undef-value-errors=',  # yes|no def-yes
    'tr_or': '--track-origins=',  # yes|no def-no
    'pr_ld': '--partial-loads-ok=',  # yes|no def-yes
    'ex_def': '--expensive-definedness-checks=',  # yes|no def-no
    # alloc|free|alloc-and-free|none def-alloc-and-free
    'kp_stk': '--keep-stacktraces=',
    'fr_vol': '--freelist-vol=',  # <number> def-20000000
    'fr_bg': '--freelist-big-blocks=',  # <number> def-1000000
    'wk_gcc': '--workaround_gcc296-bugs=',  # yes|no def-no
    'ig_rng_bl': '--ignore-range-below-sp=',  # <number>-<number>
    'sh_mm': '--show-mismatched-frees=',  # yes|no def-yes
    'ig-rngs': '--ignore-ranges=',  # 0xPP-0xQQ[,0xRR-0xSS]
    'ml_fl': '--malloc-fill=',  # <hexnumber>
    'fr_fl': '--free-fill=',  # <hexnumber>
}

dhat_opts = {
    'sh_tp': '--show-top-n=',  # <number> def - 10
    'st_by': '--sort-by=',  # <string> def- max-bytes-live
}

mass_opts = {
    'hp': '--heap=',  # yes|no def-yes
    'hp_ad': '--heap-admin=',  # <size> def - 8
    'stk': '--stacks=',  # yes|no def - no
    'pg_hp': '--pages-as-heaps=',  # yes|no def - no
    'dpt': '--depth=',  # <number> def - 30
    'al_nf': '--alloc-fn=',  # <name>
    'ig_fn': '--ignore-fn=',  # <name>
    'thd':  '--threshold=',  # <m.n>  def - 1.0
    'pk_in': '--peak-inaccuracy=',  # <m.n>  def - 1.0
    'tm_un': '--time-unit=',  # i|ms|B  def - i
    'dt_fq': '--detailed-freq=',  # <n>   def - 10
    'mx_sn': '--max-snapshots=',  # <n>   def - 100
    'ms_fl': '--massif-out-file=',  # <file> def-massif.out.%p

}

hel_opts = {
    'fr_wr': '--free-is-write=',  # no|yes def - no
    'tr_or': '--track-lockorders=',  # no|yes def - yes
    'hs_lv': '--history-level=',  # none|approx|full def - full
    'cf_cs': '--conflict-cache-size=',  # <number> def - 1000000
    'ch_rf': '--check-stack-refs=',  # no|yes def - yes
    'ig_cr': '--ignore-thread-creation=',  # yes|no def - no
}

drd_opts = {
    'ch_st': '--check-stack-var=',  # yes|no  def - no
    'ex_th': '--exclusive-threshold=',  # <number> def - off
    'jn_vl': '--join-list-vol=',  # <number> def - 10
    'ft_rc': '--first-race-only=',  # yes|no def - no
    'fr_wr': '--free-is-write=',  # yes|no def - no
    'rp_sg': '--report-signal-unlocked=',  # yes|no def - yes
    'sg_mg': '--segment-merging=',  # yes|no def - yes
    'sg_in': '--segment-merging-interval=',  # <number> def - 10
    'sh_th': '--shared-threshold=',  # <number> def - off
    'sh_cn': '--show-confl-seg=',  # yes|no def - yes
    'sh_st': '--show-stack-usage=',  # yes|no def - no
    'ig_th': '--ignore-thread-creation=',  # yes|no def - no
}

class ValgError:
    kind = ""
    what = ""
    line = ""
    
    def __init__(self, kind, what, line):
        self.kind = kind
        self.what = what
        self.line = line

class ValWrap():
    """Class ValWrap that calls valgrind and parses output

    Relies on imports re, shlex, and subprocess

    Global Class Members:
        val -- string variable for valgrind
        memCh -- string variable for running tool memcheck
        dhat -- string variable for running tool dhat
        massf -- string variable for running tool massif
        helg -- string variable for running tool helgrind
        drd -- string variable for running tool drd

    Individual Class Members:
        pName -- String variable for holding the program name
        pArgs -- List that holds arguments to be sent to file
        Output -- String that holds the output before parsing
        tool -- Specifies which tool to run

    """
    # List of tools that can be ran in Valgrind
    val = 'valgrind'
    # Finds memory leaks, overruning heap blocks, undefined var.
    memCh = 'memcheck'
    dhat = 'exp-dhat'  # Shows head usage and frees
    massf = 'massif'  # Creates visualization of heap usage
    helg = 'helgrind'  # Multithreaded lock error detector
    drd = 'drd'  # detects data races, lock contention, deadlock in multithreaded

    def __init__(self):
        """Init function for when instantiating valgrind wrapper

        Returns an instantiated class object of ValWrap

        Keyword Arguments:
            None

        Variables Instantiated:
            pName -- set to ''
            pArgs -- set to empty list
            Output -- set to ''
            tool -- set to ''
        """
        self.pName = ''  # Which program to run
        self.pArgs = []  # Program arguments
        self.Output = ''  # Output pre parsing
        self.tool = ''  # Signify which parser to run

    def setProg(self, p):  # Set program to run
        """Class method to set the program name

        Returns nothing

        Keyword Arguments:
            p -- Name of compiled program to run
        """
        self.pName = p

    def setArgs(self, lstArg):  # Set program arguments
        """Class method to pass arguments in program from command line

        Returns nothing

        Keyword Arguments:
            lstArg -- A list object with arguments
                      Ex. if program ran like ./prog arg1 arg2
                          list would be [arg1, arg2]
        """
        self.pArgs.extend(lstArg)

    def runAnlys(self, tool, tool_opts={}, err_flag=False):
        """Function to run analysis

        Pre Conditions - Expects program and program arguments to be set
        Output - Output from running valgrind

        Keyword Arguments:
            tool - which tool to run see above for which string to pass
            tool_opts - a dictionary object key correlates to dictionary object
                        above for the respective tool and the value is the
                        value to set for that option.
            err_flag - Boolean, if true valgrind won't suppress errors
        """
        self.tool = tool
        args = ' '.join(self.pArgs)
        valArg = self.pName + ' ' + args
        valArgs = self.val + ' --xml=yes --xml-fd=2 --tool='
        if tool == 'mem':
            valArgs += self.memCh+' '
            for key, val in tool_opts.items():
                valArgs += mem_opts[key]+val+' '
            if err_flag:
                valArgs += '-v '
        elif tool == 'dhat':
            valArgs += self.dhat+' '
            for key, val in tool_opts.items():
                valArgs += dhat_opts[key]+val+' '
        elif tool == 'mas':
            valArgs += self.massf+' '
            for key, val in tool_opts.items():
                valArgs += mass_opts[key]+val+' '
        elif tool == 'hel':
            valArgs += self.helg+' '
            for key, val in tool_opts.items():
                valArgs += hel_opts[key]+val+' '
        elif tool == 'drd':
            valArgs += self.drd+' '
            for key, val in tool_opts.items():
                valArgs += drd_opts[key]+val+' '
        else:
            raise ValueError('No tool recognized')
        valArgs += valArg
        prog = subprocess.Popen(
            shlex.split(valArgs),
            bufsize=64,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True)
        prog.wait()
        tempO = prog.stderr.read()
        if tool == 'mem':
            self.memOut = re.sub(
                r'(==|--)(\d+)(==|--)',
                ' ',
                tempO.decode('utf-8'))
        else:
            self.memOut = tempO.decode('utf-8')

    def getMemResults(self):
        """Class method to get to return output

        Pre-Conditions - Analysis has been ran against the program

        Return value:
            memOut - the output from valgrind
        """
        return self.memOut

    def parseOutput(self):
        root = ET.fromstring(self.memOut)
        errlist = []
        kind = ""
        what = ""
        line = ""
        for tag in root.findall('error'):
            kind = tag.find('kind').text
            if tag.find('what') is not None:
                    what = tag.find('what').text
            elif tag.find('xwhat') is not None:
                    what = tag.find('xwhat').find('text').text
            sta = tag.find('stack')
            for frame in sta.findall('frame'):
                if frame.find('line') is not None:
                    line = frame.find('line').text
                    break
            errlist.append(ValgError(kind, what, line))
        for err in errlist:
            print (err.kind + ' ' + err.what + ' at ' + err.line + "\n")

def main():
    vl = ValWrap()
    vl.setProg('./testFiles/ValTester')
    vl.setArgs(['3'])
    print('\nRunning analysis\n')
    print('Memcheck-No tool Options')
    vl.runAnlys('mem')
    print('\nResults\n')
    print(vl.getMemResults())
    print('Memcheck- tool opt - Leak-Check=Full')
    vl.runAnlys('mem', {'lk_ch': 'full'})
    print('\nResults\n')
    print(vl.getMemResults())
    print('Memcheck- tool opt - Leak-Check=Full with error flag True')
    vl.runAnlys('mem', {'lk_ch': 'full'}, True)
    print('\nResults\n')
    #print(vl.getMemResults())
    vl.parseOutput()


if __name__ == '__main__':
    main()
