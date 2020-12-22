# Author: missing
# Syscall counter - Keep a mapping of the number of syscalls executed by a given function
"""
This plugin module is intended to be run after the Syscaller plugin as it consumes
the comments created by Syscaller that annotate the syscalls.
"""

import binaryninja as bn

def run_plugin_current(bv, function):
  task = SyscallCounter(bv, [function])
  task.start()

def run_plugin_all(bv):
  task = SyscallCounter(bv, bv.functions)
  task.start()

class SyscallTracker():

  def __init__(self, function):
    self.function = function
    self.syscalls = self.record_syscalls()

  def record_syscalls(self):
    syscalls = {}

    # FIXME: Check if self.function is a Function object

    for comment in self.function.comments.values():
      if "(" in comment:
        if comment not in syscalls:
          syscalls[comment] = 1
        else:
          syscalls[comment] += 1
    return syscalls

  def log_recorded_syscalls(self):
    bn.log_info("[*] Syscall | Count")
    for syscall, count in self.syscalls.items():
      bn.log_info("[*] {} {}".format(syscall, count))


class SyscallCounter(bn.BackgroundTaskThread):

  def __init__(self, bv, functions):
    super(SyscallCounter, self).__init__('Tracking syscalls in function ...')
    self.bv = bv
    self.functions = functions
    self.visited = {}
    self.results = {}

  def traverse_breadth_first(self, function):
    queue = []
    queue.append(function)
    self.visited[function] = SyscallTracker(function)
    while len(queue) != 0:
      current_func = queue.pop()

      for callee in current_func.callees:
        if callee not in self.visited:
          queue.append(callee)
          self.visited[callee] = SyscallTracker(callee)

  def summarize_results(self):
    for tracked in self.visited.values():
      for syscall, count in tracked.syscalls.items():
        if syscall not in self.results:
          self.results[syscall] = count
        else:
          self.results[syscall] += count

  def log_syscall_count(self):
    for tracked in self.visited.values():
      if len(tracked.syscalls) != 0:
        bn.log_info("[*] Syscalls found in function {:x} {}".format(tracked.function.start, tracked.function.name))
        bn.log_info("----------------------")
        tracked.log_recorded_syscalls()
        bn.log_info("----------------------")

  def log_summarized_results(self):
    bn.log_info("[*] Summary of results, total syscall count across traversed functions")
    for syscall, count in self.results.items():
      bn.log_info("[*] {} {}".format(syscall, count))

  def run(self):

    for function in self.functions:
      self.traverse_breadth_first(function)

    self.log_syscall_count()
    self.summarize_results()
    self.log_summarized_results()

