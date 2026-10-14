# Third party provisioning roles

The four vendored CyberRangeCZ logging roles retain their upstream files and MIT license notices. They are included locally so deployment does not depend on a moving branch or a runtime Galaxy download. The wrapper uses its declared v1.0.0 sub-role dependencies.

- `sandbox-logging`: https://github.com/cyberrangecz/ansible-role-sandbox-logging, commit `f48a7806490e3b8c1f8104dbbf0d9e33c9e3e754`, MIT.
- `sandbox-logging-bash`: https://github.com/cyberrangecz/ansible-role-sandbox-logging-bash, commit `7ce0b6dc52289299e9596c6d0f2c05fb093122d8`, MIT.
- `sandbox-logging-forward`: https://github.com/cyberrangecz/ansible-role-sandbox-logging-forward, commit `3543fa8c3b1073d31e2d51e74a68ed44a9969cb5`, MIT.
- `sandbox-logging-msf`: https://github.com/cyberrangecz/ansible-role-sandbox-logging-msf, commit `e9c428ee3b1fe724b472e7270295de2c90426043`, MIT.

Source guidance: https://docs.platform.cyberrange.cz/extras/logging/how-to-use-it/ . The logging roles require Ansible 2.14 or later.
