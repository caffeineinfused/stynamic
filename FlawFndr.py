import subprocess
import shlex

class FlawFinder():
    """This class gives the ability to run flawfinder

    Uses import class subprocess and schlex

    Class Members:
        args -- the arguments (files) to give to run flawfinder
        outPut -- the output from running flawfinder
    """

    def __init__(self):
        self.args = None
        self.outPut = None

    def setArgs(self, Args):
        """Sets the arguments to pass into flawfinder

        Does not return anything

        Keyword Arguments:
            Args -- string that inludes the names of the files to run against
                    flawfinder
        """
        mainArg = 'flawfinder '
        mainArg += Args
        self.args = shlex.split(mainArg)



    def getOutPut(self):
        """Returns the output from running the analysis against a list of
        files
        """
        return self.outPut

