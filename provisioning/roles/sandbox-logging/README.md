# Ansible role - Sandbox Logging

This role represents the master Ansible role for the logging configuration of the hosts. It facilitate the usage of the following Ansible roles:

1. [sandbox-logging-bash](https://github.com/cyberrangecz/ansible-role-sandbox-logging-bash.git) - local terminal command logging.
2. [sandbox-logging-msf](https://github.com/cyberrangecz/ansible-role-sandbox-logging-msf.git) - local Metasploit command logging.
3. [sandbox-logging-forward](https://github.com/cyberrangecz/ansible-role-sandbox-logging-forward.git) - forwarding of the local logs from the sandbox host to the specified remote host.


[[_TOC_]]

## Requirements

* Bash/ZSH on the machine from which you want to collect the commands.

* The role requires root access, so you either need to specify `become` directive as a global or while invoking the role.

    ```yml
    become: yes
    ```
* The above-mentioned roles are applied to the hosts based on the Ansible variables, therefore don't disable directive `gather_facts`.
* If the role is applied to the host with Kali Linux distribution it needs to have Metasploit installed.

## Parameters

**sandbox-logging** role has neither mandatory nor optional parameters. Only sub-roles have several parameters that can be still overridden from the master role. Parameters and their descriptions are available in the README files of the above-mentioned sub-roles.

## Usage

The role sets parameter `slf_local_env` of the `sandbox-logging-forward` role to distinguish between local and cloud environments. It is done based on the available sub-roles parameters.

### Local environment
For  **local environment it is required** to set `slf_destination`, `slf_user_id` and `slf_access_token`. If `slf_user_id` and `slf_access_token` are defined, the master role will set parameter `slf_local_env` to `true` automatically.

### Cloud environment
For cloud environmnent the mandatory parameters (`global_sandbox_id`, `global_pool_id`, `hostvars['man'].ansible_host`) are already set so no additional configuration is needed. In this case, `slf_local_env` is set to `false`.

### Example

All in all, the simplest example of sandbox logging configuration looks as follows:

```
roles:
  - role: sandbox-logging
    slf_destination_port: '{% if hostvars["man"] is defined -%} 514 {%- else -%} 515 {%- endif %}'
    become: yes

```

`slf_destination_port` must be set conditionally because the host in cloud sandbox sends logs to MAN (port 514) but in a local sandbox, the logs are sent to the central Syslog (port 515).

## Caution

* Please make sure you have synchronized time of the VMs with the desired remote system, e.g. your local computer. See [chrony](https://github.com/cyberrangecz/ansible-role-chrony.git) for Linux time configuration.

* If you face up the error: **"E: Package 'python-apt' has no installation candidate"** during provisioning of the host, set up the `ansible_python_interpreter: /usr/bin/python3` variable for the host, e.g., as follows:
  ```
  - name: Configure logging
    hosts:
      - home
    ...
    vars:
      ansible_python_interpreter: /usr/bin/python3
    roles:
      - role: sandbox-logging
    ...

  ```
