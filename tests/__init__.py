import unittest
from colorama import Fore, Style, init


init(autoreset=True)


# INFO: Add color to test results
class CustomTextTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        print(Fore.GREEN + f' {test._testMethodName} passed')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(Fore.RED + f' {test._testMethodName} failed')

    def addError(self, test, err):
        super().addError(test, err)
        print(Fore.RED + f'{test._testMethodName} error')


class CustomTextTestRunner(unittest.TextTestRunner):
    resultclass = CustomTextTestResult
