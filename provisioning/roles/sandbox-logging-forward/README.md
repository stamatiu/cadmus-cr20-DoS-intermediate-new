# Ansible role - Sandbox Logging Forwarding

This role provides forwarding of the local logs from the sandbox host to the specified remote host.

[[_TOC_]]

## Requirements

* This role requires root access, so you either need to specify `become` directive as a global or while invoking the role.

    ```yml
    become: yes
    ```

## Role parameters

Mandatory parameters
* `slf_destination` - A resolvable hostname or IP address of the destination log host.

Other mandatory parameters that depend on the value of `slf_local_env` (default: `False`) parameter:
1. **Cloud environment**:
    * `slf_sandbox_id` - Sandbox ID.
    * `slf_pool_id` - Pool ID.
2. **Local environment**:
    * `slf_user_id` - User ID.
    * `slf_access_token` - Access token of the training instance.

Mandatory parameters - local environment
* `slf_user_id` - User ID.
* `slf_access_token` - Access token of the training instance.

Optional parameters
* `slf_sandbox_name` - Sandbox name (default: `None`).
* `slf_destination_port` - Remote host destination port (default: `514`).
* `slf_destination_protocol` - The transport protocol used for transmission of the logs to the remote host. Values 'tcp', 'tls' and 'udp' are supported. (default: `tcp`).
* `slf_forward_log_severity` - Severity of the forwarded log entries (default: `*`).
* `slf_tag_regexes` - Filter messages based on the Syslog tags that matches one of these regexes (default: `['bash.command', 'msf.command']`)

### Encrypted communication
To use encrypted communication you must set `slf_destination_protocol` to `tls` and set the following parameter:
* `slf_rsyslog_ca_cert_file` - Path to the trusted CA certificate (default: `None`).

To use **mutual authentication** set the following parameters:
* `slf_rsyslog_cert_file` - Path to the client certificate in PEM format matching the private key set in the `slf_rsyslog_key_file` (default: `None`).
* `slf_rsyslog_key_file` - Path to the unencrypted client private key in PEM format. Define this variable to enable **encrypted communication** (default: `None`). TCP protocol must be set.

## Example

The simplest example of sandbox logging forward configuration.

```
roles:
  - role: sandbox-logging-forward
    slf_destination: 192.168.0.5
    slf_sandbox_id: sandbox-1
    become: yes

```

## Caution

* Please make sure you have synchronized time of the VMs with the desired remote system, e.g. your local computer. See [chrony](https://github.com/cyberrangecz/ansible-role-chrony.git) for Linux time configuration.
