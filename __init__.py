#!/usr/bin/env python
# author: carstein <michal.melewski@gmail.com>
# Syscaller - decoreate syscall with arguments

from binaryninja import PluginCommand

from .modules import libcaller
from .modules import syscaller
from .modules import syscall_counter

# register plugin
PluginCommand.register_for_function(
  "Syscaller\Decorate syscalls in current function",
  "Annotate syscalls with arguments in current function",
  syscaller.run_plugin_current)

PluginCommand.register(
  "Syscaller\Decorate syscalls in all functions",
  "Annotate syscalls with arguments in all defined functions",
  syscaller.run_plugin_all)

PluginCommand.register_for_function(
  "Syscall_Counter\Record the number of syscalls in current function",
  "Record a hashmap of the number of times a particular syscall is present in the current function, traversing with breadth-first-search",
  syscall_counter.run_plugin_current)

PluginCommand.register(
  "Syscall_Counter\Record the number of syscalls in all functions",
  "Record a hashmap of the number of times a particular syscall is present in all defined functions",
  syscall_counter.run_plugin_all)

PluginCommand.register_for_function(
  "Libcaller\Identify library function calls called by the current function",
  "Record the library calls called by a function, traversing with breadth-first-search",
  libcaller.run_plugin_current)

