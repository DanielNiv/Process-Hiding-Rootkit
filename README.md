# Process-Hiding-Rootkit
A Loadable Kernel Module (LKM) Rootkit that hooks the system call table and hides the chosen process(according to your parameter) from 'ls' and 'ps' commands. The Rootkit hijacks stat and getdents system calls.
