# Ansible role - Sandbox Logging Msfconsole Commands

This role provides local Metasploit command logging.

By default, the Metasploit commands history contains only correct/known commands. The role modifies the `/lib/rex/ui/text/shell.rb` file so it records also the incorrect commands to the history file.

**Warning**: This role only affects users known at the time of its execution. As a result, any [user-access](https://github.com/cyberrangecz/ansible-role-user-access.git) role has to be specified and executed prior to the execution of the sandbox-logging-msf role.

## Requirements

* Metasploit

* This role requires root access, so you either need to specify `become` directive as a global or while invoking the role.

    ```yml
    become: yes
    ```

* Also requires Ansible variables, therefore do not disable directive `gather_facts`.

## Role parameters

No parameters

## Example

The simplest example of logging msf commands configuration.

```
  roles:
    - role: sandbox-logging-msf
      become: yes
```
