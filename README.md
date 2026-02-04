# InSpec-Windows-2022-CIS-Baseline

# CIS Microsoft Windows Server 2022 Baseline (InSpec)

This repository is an InSpec compliance profile for auditing a Windows Server 2022 host against CIS benchmark settings.

## Run

1. Update `inputs.yml` for your environment.
2. Execute the profile. Example:

```bash
inspec exec . -t winrm://Administrator@HOST --password 'PASSWORD' --input-file inputs.yml
```
