# Author: missing
# Library caller - Identify the library function calls called by a function

import binaryninja as bn

from binaryninja.enums import SymbolType

def run_plugin_current(bv, function):
  task = LibCallerTask(bv, [function])
  task.start()

def run_plugin_all(bv):
  task = LibCallerTask(bv, bv.functions)
  task.start()

class LibCallerTask(bn.BackgroundTaskThread):

  def __init__(self, bv, functions):
    super(LibCallerTask, self).__init__('Identifying library calls')
    self.bv = bv
    self.imported_functions = bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
    self.functions = functions
    self.visited = {}
    self.libcalls = []

  def traverse_breadth_first(self, function):
    queue = []
    queue.append(function)
    self.visited[function] = True

    while len(queue) != 0:
      current_func = queue.pop()

      if current_func.symbol in self.imported_functions:
        bn.log_info(current_func.name)
        self.libcalls.append(current_func.name)

      for callee in current_func.callees:
        if callee not in self.visited:
          queue.append(callee)
          self.visited[callee] = True 

  def run(self):
    for function in self.functions:
      self.traverse_breadth_first(function)

