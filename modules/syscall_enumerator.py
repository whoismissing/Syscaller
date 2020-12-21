# Author: missing
# Syscall Enumerator - Enumerate the syscalls contained within a section of code

import binaryninja as bn

from . import syscaller
from .libcaller import LibCallerTask
from .syscall_counter import SyscallCounter

def run_plugin_current(bv, function):
  task = SyscallEnumerator(bv, [function])
  task.start()

def run_plugin_all(bv):
  task = SyscallEnumerator(bv, bv.functions)
  task.start()

def get_lib_paths():
  lib_paths = []
  user_prompt = "Enter the file path to the library binaries,"
  user_prompt += " each on a separate line"

  user_input = bn.interaction.MultilineTextField(user_prompt)
  bn.interaction.get_form_input(["Enter libraries", user_input], "")

  if user_input.result:
    lib_paths = user_input.result.split("\n")

  return lib_paths

def analyze_lib_files(lib_paths, libcalls):
  libs = []
  counters = []
  for lib in lib_paths:
    lib_bv = bn.BinaryViewType.get_view_of_file(lib)
    lib_bv.add_analysis_option("linearsweep")
    lib_bv.add_analysis_option("signaturematcher")
    lib_bv.update_analysis_and_wait()

    task = syscaller.run_plugin_get_task(lib_bv)
    while not task.finished:
      continue

    libs.append(lib_bv)

    bn.log_info("Analyzing library:") # REMOVEME
    bn.log_info(lib)

    for func in lib_bv.functions:
      if func.name in libcalls:
        bn.log_info(func.name)
        counter = SyscallCounter(lib_bv, [func])
        counter.start()
        while not counter.finished:
          continue
        counters.append(counter)

    bn.log_info("Counters = ")
    bn.log_info(str(counters))

class SyscallEnumerator(bn.BackgroundTaskThread):

  def __init__(self, bv, functions):
    super(SyscallEnumerator, self).__init__('Enumerating syscalls')
    self.bv = bv
    self.functions = functions

  def run(self):
    syscaller.run_plugin_all(self.bv)

    libcaller = LibCallerTask(self.bv, self.functions)
    libcaller.start()

    while not libcaller.finished:
      continue

    num_libcalls = len(libcaller.libcalls)
    lib_paths = []
    if num_libcalls > 0:
      lib_paths = get_lib_paths()

    analyze_lib_files(lib_paths, libcaller.libcalls)

