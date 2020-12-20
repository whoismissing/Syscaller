BinaryNinja Syscall annotator
====================
This is a plugin for Binary Ninja Reversing Platform.
Upon encountering a syscall it gets annotated with retrieved arguments.

Some additional modules have been added to the original Syscaller plugin.

Additionally, the original Syscaller plugin has been patched to exclude searching for syscall arguments since there is currently an out-of-bounds indexing error.

#### Modules
* [Syscall Counter](./modules/syscall_counter.py) - Record a mapping of the number of syscalls executed by a given function using breadth-first-search. Reliant on stashing the comments annotated by Syscaller.
* [Libcaller](./modules/libcaller.py) - Record the library functions called by a given function using breadth-first-search.
