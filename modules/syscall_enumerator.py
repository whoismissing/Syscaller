# Author: missing
# Syscall Enumerator - Enumerate the syscalls contained within a section of code
"""
This plugin module is intended to be used to enumerate the syscalls
executed by a dynamically linked executable binary file. It is 
accomplished by scanning for imported library calls from the current
function, then based on user-specified file paths to library binaries,
the library calls in those library binaries are enumerated for their syscalls.

Essentially:
1. Run Libcaller on the current dynamically-linked binary's current function
2. Get file paths to the libraries linked in the binary from the user
3. Optionally run Syscaller on the library binary file
4. Run SyscallCounter on matching library functions called by the target binary
4. Summarize results
"""

import binaryninja as bn

from . import syscaller
from .libcaller import LibCallerTask
from .syscall_counter import SyscallCounter

def run_plugin_current(bv, function):
  task = SyscallEnumerator(bv, [function])
  task.start()

def get_lib_file_paths():
  """
  Get plugin options from the user.
  Options include:
  * full paths to library binary files
  * flag to run Syscaller on the library binary files
  """
  lib_paths = []
  user_prompt = "Enter the file path to the library binaries,"
  user_prompt += " each on a separate line"

  user_input = bn.interaction.MultilineTextField(user_prompt)
  bn.interaction.get_form_input(["Enter libraries", user_input], "")

  if user_input.result:
    lib_paths = user_input.result.split("\n")

  # FIXME: Validate user input for readable file paths and remove empty strings
  # FIXME: Get flag from user input to decide whether to run Syscaller or not

  return lib_paths

def get_binary_view(binary):
  """
  Return the analyzed binary view object given a binary or database file path.
  """
  view = bn.BinaryViewType.get_view_of_file(binary)
  view.add_analysis_option("linearsweep")
  view.add_analysis_option("signaturematcher")
  view.update_analysis_and_wait()
  return view

def run_libcaller_blocking(view, funcs):
  """
  Run the LibCaller plugin module and wait for the task to finish.
  Return the object representing the LibCaller task.
  """
  task = LibCallerTask(view, funcs)
  task.start()
  while not task.finished:
    continue
  return task

def run_syscaller_blocking(view):
  """
  Run the SysCaller plugin module and wait for the task to finish.
  Return the object representing the SysCaller task.
  """
  task = syscaller.run_plugin_get_task(view)
  while not task.finished:
    continue
  return task

def run_syscall_counter_blocking(view, func):
  """
  Run the SyscallCounter plugin module and wait for the task to finish.
  Return the object representing the SyscallCounter task.
  """
  task = SyscallCounter(view, [func])
  task.start()
  while not task.finished:
    continue
  return task

class SyscallEnumerator(bn.BackgroundTaskThread):

  def __init__(self, bv, functions):
    super(SyscallEnumerator, self).__init__('Enumerating syscalls')
    self.bv = bv
    self.functions = functions
    self.libcalls = None
    self.lib_bvs = []
    self.syscall_counters = []

  def enumerate_syscalls(self, view):
    for func in view.functions:
      if func.name in self.libcalls:
        counter = run_syscall_counter_blocking(view, func)
        self.syscall_counters.append(counter)

  def analyze_lib_file(self, lib):
    bn.log_info("[*] Analyzing library {}".format(lib))

    lib_bv = get_binary_view(lib) 

    # FIXME: Add flag to run Syscaller optionally
    run_syscaller_blocking(lib_bv)

    self.lib_bvs.append(lib_bv)
    self.enumerate_syscalls(lib_bv)

  def analyze_lib_files(self, lib_files):
    for lib in lib_files:
      self.analyze_lib_file(lib) 

      # FIXME: Summarize syscall counters
      bn.log_info("Counters = ")
      bn.log_info(str(self.syscall_counters))

  def run(self):
    libcaller = run_libcaller_blocking(self.bv, self.functions)

    num_libcalls = len(libcaller.libcalls)
    lib_files = []
    if num_libcalls > 0:
      lib_files = get_lib_file_paths()
      self.libcalls = libcaller.libcalls

    if self.libcalls:
      self.analyze_lib_files(lib_files)

