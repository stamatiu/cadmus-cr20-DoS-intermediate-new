Ansible role - Sandbox Logging Commands
=========

This role provides local terminal command logging.

## Supported OS
The role supports the following operating systems.

 * Ubuntu 20.04
 * Debian 10
 * Kali Linux 2019.4
 * CentOS 8

 Other operating systems haven't been tested yet and the role might not be working on them.


## Requirements

* Bash

* This role requires root access, so you either need to specify `become` directive as a global or while invoking the role.

    ```yml
    become: yes
    ```

* Also requires Ansible variables, therefore do not disable directive `gather_facts`.

## Role parameters

No parameters

## Example

The simplest example of logging bash commands configuration.

```
  roles:
    - role: sandbox-logging-bash
      become: yes
```

## FAQ

Q: What is the character limit per a single log record?\
A: It depends on the local implementation of Rsyslog. Usually, it is several hundreds or even thousands of characters, which is completely sufficient for almost all use cases.

Q: If I open a nested shell within the current shell, is the content logged?\
A: Yes.

Q: If I write the commands in a shell script and then run the script, is it logged?\
A: Only the action of running the script is logged, e.g., `./myscript.sh`. The content of the script itself is not logged.

Q: Can the toolset be extended with logging more metadata?\
A: It is possible to add the logging of environment variables (e.g., `$HOME`), available files in the given folder, and other [syslog macros](https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.16/administration-guide/58).

Q: Double quotes (") are used as a separator of the log entries. What happens if a user inputs them as a part of the command?\
A: Double quotes in Bash commands are correctly escaped by a backslash.

Q: If I wanted to extend this role, how can I contribute?\
A: Interesting possibilities for future work include:
* Logging terminal output (`stdout` and `stderr`), for example, for better error analysis of the log data.
* Logging the process ID of the opened terminal, for example, to recognize when a student worked in multiple command lines in parallel.
