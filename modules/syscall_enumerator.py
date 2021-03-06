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

def get_plugin_options():
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
  if view is None:
    bn.log_error("Binary ninja returned view <None>")
  view.add_analysis_option("linearsweep")
  view.add_analysis_option("signaturematcher")
  view.update_analysis_and_wait()
  return view

def get_libcaller_blocking(view, funcs):
  """
  Run the LibCaller plugin module and wait for the task to finish.
  Return the object representing the LibCaller task.
  """
  task = LibCallerTask(view, funcs)
  task.start()
  while not task.finished:
    continue
  return task

def get_syscaller_blocking(view):
  """
  Run the SysCaller plugin module and wait for the task to finish.
  Return the object representing the SysCaller task.
  """
  task = syscaller.run_plugin_get_task(view)
  while not task.finished:
    continue
  return task

def get_syscall_counter_blocking(view, func):
  """
  Run the SyscallCounter plugin module and wait for the task to finish.
  Return the object representing the SyscallCounter task.
  """
  task = SyscallCounter(view, func)
  task.start()
  while not task.finished:
    continue
  return task

class SyscallEnumerator(bn.BackgroundTaskThread):

  """This module analyzes an executable binary file
  and traverses over a list of functions, following
  library calls through library files to determine the
  syscalls used by a given list of functions.

  Args:
    view: A binary view of the file being analyzed.
    functions: A list of function objects to traverse.

  Attributes:
    view: A binary view of the file being analyzed.
    functions: A list of function objects to traverse.
    libcalls: A list of library functions used by the functions being visited.
    lib_view: A list of binary view objects for libraries used by the file being analyzed.
    syscall_counters: A list of SyscallCounter objects
    summarized_results: A dictionary
  """
  def __init__(self, view, functions):
    super(SyscallEnumerator, self).__init__('Enumerating syscalls')
    self.view = view
    if type(functions) != list:
      functions = [functions]
    self.functions = functions
    self.libcalls = None
    self.lib_views = []
    self.syscall_counters = []
    self.summarized_results = {}

  def run(self):
    bn.log_info("SyscallEnumerator started")
    libcaller = get_libcaller_blocking(self.view, self.functions)

    num_libcalls = len(libcaller.libcalls)
    lib_files = []

    if num_libcalls == 0:
      bn.log_error("Number of library calls is 0, exiting")
      bn.log_info("SyscallEnumerator finished")
      return

    if num_libcalls > 0:
      lib_files = get_plugin_options()
      self.libcalls = libcaller.libcalls

    if self.libcalls:
      self.analyze_lib_files(lib_files)

    bn.log_info("-----------------------------")
    bn.log_info("[*] Summarized results for syscalls recorded from imported libraries:")
    for lib in lib_files:
      bn.log_info("[*] Library {}".format(lib))
    self.summarize_results()

    self.log_summarized_results()
    bn.log_info("-----------------------------")
    bn.log_info("SyscallEnumerator finished")

  def analyze_lib_files(self, lib_files):
    for lib in lib_files:
      self.analyze_lib_file(lib) 

  def analyze_lib_file(self, lib):
    bn.log_info("[*] Analyzing library {}".format(lib))

    lib_view = get_binary_view(lib) 
    if lib_view is None:
      bn.log_error("The library file was unable to be analyzed, view returned <None>")

    # FIXME: Add flag to run Syscaller optionally
    get_syscaller_blocking(lib_view)

    self.lib_views.append(lib_view)
    self.enumerate_syscalls(lib_view)

  def enumerate_syscalls(self, view):
    for func in view.functions:
      if func.name in self.libcalls:
        syscall_counter = get_syscall_counter_blocking(view, func)
        self.syscall_counters.append(syscall_counter)

  def summarize_results(self):
    for counter in self.syscall_counters:
      for syscall, count in counter.results.items():
        if syscall not in self.summarized_results:
          self.summarized_results[syscall] = count
        else:
          self.summarized_results[syscall] += count

  def log_summarized_results(self):
    for syscall, count in self.summarized_results.items():
      bn.log_info("[*] {} {}".format(syscall, count))

