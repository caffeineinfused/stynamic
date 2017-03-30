#!/usr/bin/python3
import re
import subprocess
import shlex

mem_opts ={                             #Options in comments
    'lk_ch': '--leak-check=',                       #no|summary|yes|fill def-Sum
    'lk_res': '--leak-resolution=',                 #low|med|high def-high
    'sh_lk': '--show-leak-kinds=',                  #<set> def-definite,possible
    'er_lk': '--errors-for-leak-kinds=',            #<set> def-all
    'lk_hr': '--leak-check-heuristics=',            #<set> def-all
    'sh_re': '--show-reachable=',                   #yes|no
    'sh_pLst': '--show-possibly-lost=',             #yes|no
    'und_er': '--undef-value-errors=',              #yes|no def-yes
    'tr_or': '--track-origins=',                    #yes|no def-no
    'pr_ld': '--partial-loads-ok=',                 #yes|no def-yes
    'ex_def': '--expensive-definedness-checks=',    #yes|no def-no
    'kp_stk': '--keep-stacktraces=',    #alloc|free|alloc-and-free|none def-alloc-and-free
    'fr_vol': '--freelist-vol=',                    #<number> def-20000000
    'fr_bg': '--freelist-big-blocks=',              #<number> def-1000000
    'wk_gcc': '--workaround_gcc296-bugs=',          #yes|no def-no
    'ig_rng_bl': '--ignore-range-below-sp=',        #<number>-<number>
    'sh_mm': '--show-mismatched-frees=',            #yes|no def-yes
    'ig-rngs': '--ignore-ranges=',                  #0xPP-0xQQ[,0xRR-0xSS]
    'ml_fl': '--malloc-fill=',                      #<hexnumber>
    'fr_fl': '--free-fill=',                        #<hexnumber>
}

class ValWrap():
    #List of tools that can be ran in Valgrind
    val = 'valgrind'
    memCh = 'memcheck' #Finds memory leaks, overruning heap blocks, undefined var.
    dhat = 'exp-dhat' #Shows head usage and frees
    massf = 'massif' #Creates visualization of heap usage
    helg = 'helgrind' #Multithreaded lock error detector
    drd = 'drd' #detects data races, lock contention, deadlock in multithreaded

    def __init__(self):
        self.pName = ''                 #Which program to run
        self.pArgs = []                 #Program arguments
        self.Output = ''                #Output pre parsing
        self.tool = ''                  #Signify which parser to run

    def setProg(self, p):               #Set program to run
        self.pName = p

    def setArgs(self, lstArg):          #Set program arguments
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
        valArg = self.pName +' '+ args
        valArgs = self.val + ' --tool='
        if tool == 'mem':
            valArgs += self.memCh+' '
            for key, val in tool_opts.items():
                valArgs += mem_opts[key]+val+' '
            if err_flag:
                valArgs += '-v '
        elif tool == 'dhat':
            valArgs += self.dhat+' '
        elif tool == 'mas':
            valArgs += self.massf+' '
        elif tool == 'hel':
            valArgs += self.helg+' '
        elif tool == 'drd':
            valArgs += self.drd+' '
        else:
            raise ValueError('No tool recognized')
        valArgs += valArg
        prog = subprocess.Popen(shlex.split(valArgs), bufsize=64, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        prog.wait()
        tempO = prog.stderr.read()
        self.memOut = re.sub(r'(==|--)(\d+)(==|--)',' ', tempO.decode('utf-8'))

    def getMemResults(self):
        return self.memOut


def main():
    vl = ValWrap()
    vl.setProg('./testFiles/ValTester')
    vl.setArgs(['1'])
    print('\nRunning analysis\n')
    print('Memcheck-No tool Options')
    vl.runAnlys('mem')
    print('\nResults\n')
    print(vl.getMemResults())
    print('Memcheck- tool opt - Leak-Check=Full')
    vl.runAnlys('mem', {'lk_ch':'full'})
    print('\nResults\n')
    print(vl.getMemResults())
    print('Memcheck- tool opt - Leak-Check=Full with error flag True')
    vl.runAnlys('mem', {'lk_ch':'full'}, True)
    print('\nResults\n')
    print(vl.getMemResults())


if __name__ == '__main__': main()
