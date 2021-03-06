#!/usr/bin/python3

from qiling import *
from qiling.utils import *

def remove_parentheses(string):
    string = string.replace("(", "")
    string = string.replace(")", "")
    return string

def get_ql_syscall_name(syscall_name):
    ql_syscall_name = "ql_syscall_" + syscall_name
    return ql_syscall_name

def get_enumerated_syscalls(filename):
    syscalls = []

    data = ''
    with open(filename, "r") as fd:
        data = fd.read()

    lines = data.split('\n')
    for line in lines:
        if line == "":
            break
        syscall_with_parentheses = line.split(" ")[1]
        syscall = remove_parentheses(syscall_with_parentheses)
        ql_syscall = get_ql_syscall_name(syscall)
        syscalls.append(ql_syscall)
    return syscalls

def main():
    syscalls = get_enumerated_syscalls("./enumerated_syscalls.txt")
    module = "qiling.os.posix.syscall"

    for syscall in syscalls:
        try:
            ql_get_module_function(module, syscall)
        except exception.QlErrorModuleFunctionNotFound:
            print(f"{syscall} needs to be implemented!")

main()

