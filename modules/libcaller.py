# Author: missing
# Library caller - Identify the library function calls called by a function

import binaryninja as bn

from binaryninja.enums import SymbolType

def run_plugin_current(view, function):
  task = LibCallerTask(view, [function])
  task.start()

def run_plugin_all(view):
  task = LibCallerTask(view, view.functions)
  task.start()

class LibCallerTask(bn.BackgroundTaskThread):

  """This module analyzes an executable binary file
  and traverses over all functions or a single function
  to determine the library calls used.

  Args:
    view: A binary view of the file being analyzed.
    functions: A list of function objects to traverse.

  Attributes:
    view: A binary view of the file being analyzed.
    imported_functions: A list of function objects imported externally by the file. aka list of library functions.
    functions: A list of function objects to traverse.
    visited: A list of functions visited during callee traversal.
    libcalls: A list of library functions used by the functions being visited.
  """
  def __init__(self, view, functions):
    super(LibCallerTask, self).__init__('Identifying library calls')
    self.view = view
    self.imported_functions = view.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
    if type(functions) != list:
      functions = [functions]
    self.functions = functions
    self.visited = []
    self.libcalls = []

  def run(self):
    bn.log_info("LibCaller started")
    for function in self.functions:
      self.traverse_breadth_first(function)
    bn.log_info("LibCaller finished")

  def traverse_breadth_first(self, function):
    queue = []
    queue.append(function)
    self.visited.append(function)

    while len(queue) != 0:
      current_func = queue.pop()

      matched_library_call = current_func.symbol in self.imported_functions
      if matched_library_call:
        bn.log_info("[*] Traversing {} at 0x{:x}".format(current_func.name, current_func.start))
        self.libcalls.append(current_func.name)

      for callee in current_func.callees:
        if callee not in self.visited:
          queue.append(callee)
          self.visited.append(callee)

