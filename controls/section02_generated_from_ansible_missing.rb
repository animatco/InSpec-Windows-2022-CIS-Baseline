# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 02 — Local Policies (Generated)
#  Source: Windows-2022-CIS-devel Ansible hardening tasks
#  Notes:
#   - Generated controls cover CIS rules present in Ansible tasks but missing
#     from the baseline profile at generation time.
#   - Registry, User Rights, and Security Policy checks are implemented using
#     InSpec native resources and local_security_policy export parsing.
###############################################
only_if("Section 02 disabled by input") do
  input("run_section_02")
end

control 'cis-2.2.41' do
  impact 1.0
  title 'Ensure Modify firmware environment values is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.41. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.41'

  describe user_right('SeSystemEnvironmentPrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.2.42' do
  impact 1.0
  title 'Ensure Perform volume maintenance tasks is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.42. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.42'

  describe user_right('SeManageVolumePrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.2.43' do
  impact 1.0
  title 'Ensure Profile single process is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.43. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.43'

  describe user_right('SeProfileSingleProcessPrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.2.44' do
  impact 1.0
  title 'Ensure Profile system performance is set to Administrators NT SERVICE.WdiServiceHost'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.44. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.44'

  describe user_right('SeSystemProfilePrivilege') do
    its('value') { should match_array(['Administrators', 'NT SERVICE\\WdiServiceHost']) }
  end
end


control 'cis-2.2.45' do
  impact 1.0
  title 'Ensure Replace a process level token is set to LOCAL SERVICE NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.45. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.45'

  describe user_right('SeAssignPrimaryTokenPrivilege') do
    its('value') { should match_array(['LOCAL SERVICE', 'NETWORK SERVICE']) }
  end
end


control 'cis-2.2.46' do
  impact 1.0
  title 'Ensure Restore files and directories is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.46. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.46'

  describe user_right('SeRestorePrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.2.47' do
  impact 1.0
  title 'Ensure Shut down the system is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.47. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.47'

  describe user_right('SeShutdownPrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.2.48' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.48. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.48'

  describe user_right('SeSyncAgentPrivilege') do
    its('value') { should match_array([]) }
  end
end


control 'cis-2.2.49' do
  impact 1.0
  title 'Ensure Take ownership of files or other objects is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.49. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.49'

  describe user_right('SeTakeOwnershipPrivilege') do
    its('value') { should match_array(['Administrators']) }
  end
end


control 'cis-2.3.1.4' do
  impact 1.0
  title 'Configure Accounts Rename guest account'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.1.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.1.4'

  describe local_security_policy do
    its('NewGuestName') { should cmp 'guestchangethis' }
  end
end


control 'cis-2.3.2.2' do
  impact 1.0
  title 'Ensure Audit Shut down system immediately if unable to log security audits is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.2.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.2.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('CrashOnAuditFail') should cmp 0
  end
end


control 'cis-2.3.5.1' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.5.1'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SubmitControl') should cmp 0
  end
end


control 'cis-2.3.5.2' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.5.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('VulnerableChannelAllowList') should cmp 0
  end
end


control 'cis-2.3.5.3' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.5.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LdapEnforceChannelBinding') should cmp 2
  end
end


control 'cis-2.3.5.4' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.5.4'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') do
    its('LDAPServerIntegrity') should cmp 2
  end
end


control 'cis-2.3.5.5' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.5.5'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RefusePasswordChange') should cmp 0
  end
end


control 'cis-2.3.6.2' do
  impact 1.0
  title 'Ensure Domain member Digitally encrypt secure channel data when possible is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.6.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SealSecureChannel') should cmp 1
  end
end


control 'cis-2.3.6.3' do
  impact 1.0
  title 'Ensure Domain member Digitally sign secure channel data when possible is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.6.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SignSecureChannel') should cmp 1
  end
end


control 'cis-2.3.6.4' do
  impact 1.0
  title 'Ensure Domain member Disable machine account password changes is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.6.4'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('DisablePasswordChange') should cmp 0
  end
end


control 'cis-2.3.6.5' do
  impact 1.0
  title 'Ensure Domain member Maximum machine account password age is set to 30 or fewer days but not 0'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.6.5'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('MaximumPasswordAge') should cmp 30
  end
end


control 'cis-2.3.6.6' do
  impact 1.0
  title 'Ensure Domain member Require strong Windows 2000 or later session key is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.6. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.6.6'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireStrongKey') should cmp 1
  end
end


control 'cis-2.3.7.5' do
  impact 1.0
  title 'Configure Interactive logon Message title for users attempting to log on'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.7.5'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('LegalNoticeCaption') should cmp 'DoD Notice and Consent Banner'
  end
end


control 'cis-2.3.7.6' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.6. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.7.6'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('CachedLogonsCount') should cmp 1
  end
end


control 'cis-2.3.7.7' do
  impact 1.0
  title 'Ensure Interactive logon Prompt user to change password before expiration is set to between 5 and 14 days'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.7. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.7.7'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('PasswordExpiryWarning') should cmp 14
  end
end


control 'cis-2.3.7.8' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.8. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.7.8'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('ForceUnlockLogon') should cmp 1
  end
end


control 'cis-2.3.7.9' do
  impact 1.0
  title 'Ensure Interactive logon Smart card removal behavior is set to Lock Workstation or higher.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.9. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.7.9'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows Nt\\CurrentVersion\\Winlogon') do
    its('ScRemoveOption') should cmp 1
  end
end


control 'cis-2.3.8.3' do
  impact 1.0
  title 'Ensure Microsoft network client Send unencrypted password to third-party SMB servers is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.8.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.8.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('EnablePlainTextPassword') should cmp 0
  end
end


control 'cis-2.3.9.3' do
  impact 1.0
  title 'Ensure Microsoft network server Digitally sign communications if client agrees is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.9.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('EnableSecuritySignature') should cmp 1
  end
end


control 'cis-2.3.9.4' do
  impact 1.0
  title 'Ensure Microsoft network server Disconnect clients when logon hours expire is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.9.4'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('EnableForcedLogoff') should cmp 1
  end
end


control 'cis-2.3.9.5' do
  impact 1.0
  title 'MS Only'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.9.5'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('SMBServerNameHardeningLevel') should cmp 1
  end
end


control 'cis-2.3.10.1' do
  impact 1.0
  title 'Ensure Network access Allow anonymous SID/Name translation is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.1'

  describe local_security_policy do
    its('LSAAnonymousNameLookup') { should cmp 0 }
  end
end


control 'cis-2.3.10.2' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.10.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymousSAM') should cmp 1
  end
end


control 'cis-2.3.10.3' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.10.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictAnonymous') should cmp 1
  end
end


control 'cis-2.3.10.4' do
  impact 1.0
  title 'Ensure Network access Do not allow storage of passwords and credentials for network authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 2 controls disabled') { input('run_level_2') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.4'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('DisableDomainCreds') should cmp 1
  end
end


control 'cis-2.3.10.5' do
  impact 1.0
  title 'Ensure Network access Let Everyone permissions apply to anonymous users is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.5'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('EveryoneIncludesAnonymous') should cmp 0
  end
end


control 'cis-2.3.10.6' do
  impact 1.0
  title 'Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.6. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.10.6'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('NullSessionPipes') should cmp ['LSARPC', 'NETLOGON', 'SAMR']
  end
end


control 'cis-2.3.10.7' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.7. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.10.7'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('NullSessionPipes') should cmp ''
  end
end


control 'cis-2.3.10.8' do
  impact 1.0
  title 'Configure Network access Remotely accessible registry paths'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.8. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.8'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Securepipeservers\\Winreg\\AllowedExactpaths') do
    its('Machine') should cmp ['SYSTEM\\CurrentControlSet\\Control\\ProductOptions', 'SYSTEM\\CurrentControlSet\\Control\\Server Applications', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion']
  end
end


control 'cis-2.3.10.9' do
  impact 1.0
  title 'Configure Network access Remotely accessible registry paths and sub-paths'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.9. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.9'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Securepipeservers\\Winreg\\Allowedpaths') do
    its('Machine') should cmp '{{ rule_2_3_10_9_remote_registry_paths }}'
  end
end


control 'cis-2.3.10.10' do
  impact 1.0
  title 'Ensure Network access Restrict anonymous access to Named Pipes and Shares is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.10. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.10'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('RestrictNullSessAccess') should cmp 1
  end
end


control 'cis-2.3.10.11' do
  impact 1.0
  title 'Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.11. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'member_server' }

  tag cis_id: '2.3.10.11'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('RestrictRemoteSAM') should cmp 'O:BAG:BAD:(A;;RC;;;BA)'
  end
end


control 'cis-2.3.10.12' do
  impact 1.0
  title 'Ensure Network access Shares that can be accessed anonymously is set to None'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.12. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.12'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters') do
    its('NullSessionShares') should cmp ''
  end
end


control 'cis-2.3.10.13' do
  impact 1.0
  title 'Ensure Network access Sharing and security model for local accounts is set to Classic - local users authenticate as themselves'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.10.13. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.10.13'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('ForceGuest') should cmp 0
  end
end


control 'cis-2.3.11.1' do
  impact 1.0
  title 'Ensure Network security Allow Local System to use computer identity for NTLM is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.1'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('UseMachineId') should cmp 1
  end
end


control 'cis-2.3.11.2' do
  impact 1.0
  title 'Ensure Network security Allow LocalSystem NULL session fallback is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('AllowNullSessionFallback') should cmp 0
  end
end


control 'cis-2.3.11.3' do
  impact 1.0
  title 'Ensure Network Security Allow PKU2U authentication requests to this computer to use online identities is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.3'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Pku2U') do
    its('AllowOnlineID') should cmp 0
  end
end


control 'cis-2.3.11.4' do
  impact 1.0
  title 'Ensure Network security Configure encryption types allowed for Kerberos is set to AES128 HMAC SHA1 AES256 HMAC SHA1 Future encryption types'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.4'

  describe registry_key('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    its('SupportedEncryptionTypes') should cmp 2147483644
  end
  describe registry_key('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters') do
    its('SupportedEncryptionTypes') should cmp 2147483640
  end
end


control 'cis-2.3.11.5' do
  impact 1.0
  title 'Ensure Network security Do not store LAN Manager hash value on next password change is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.5'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('NoLMHash') should cmp 1
  end
end


control 'cis-2.3.11.6' do
  impact 1.0
  title 'Ensure Network security Force logoff when logon hours expire is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.6. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.6'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters') do
    its('EnableForcedLogOff') should cmp 1
  end
end


control 'cis-2.3.11.7' do
  impact 1.0
  title 'Ensure Network security LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM NTLM'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.7. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.7'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('LMCompatibilityLevel') should cmp 5
  end
end


control 'cis-2.3.11.8' do
  impact 1.0
  title 'Ensure \'Network security: LDAP client encryption requirements\' is set to \'Negotiate sealing\' or higher.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.8. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.8'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Ldap') do
    its('LDAPClientConfidentiality') should cmp 1
  end
end


control 'cis-2.3.11.9' do
  impact 1.0
  title 'Ensure Network security LDAP client signing requirements is set to Negotiate signing or higher.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.9. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.9'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Ldap') do
    its('LDAPClientIntegrity') should cmp 1
  end
end


control 'cis-2.3.11.10' do
  impact 1.0
  title 'Ensure Network security Minimum session security for NTLM SSP based including secure RPC clients is set to Require NTLMv2 session security Require 128-bit encryption'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.10. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.10'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('NTLMMinClientSec') should cmp 537395200
  end
end


control 'cis-2.3.11.11' do
  impact 1.0
  title 'Ensure Network security Minimum session security for NTLM SSP based including secure RPC servers is set to Require NTLMv2 session security Require 128-bit encryption'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.11. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.11'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Msv1_0') do
    its('NTLMMinServerSec') should cmp 537395200
  end
end


control 'cis-2.3.11.12' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Audit Incoming NTLM Traffic is set to Enable auditing for all accounts'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.12. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.12'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('AuditReceivingNTLMTraffic') should cmp 2
  end
end


control 'cis-2.3.11.13' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Audit NTLM authentication in this domain is set to Enable all DC Only'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.13. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.11.13'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('AuditNTLMInDomain') should cmp 7
  end
end


control 'cis-2.3.11.14' do
  impact 1.0
  title 'Ensure Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers is set to Audit all or higher.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.11.14. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.11.14'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0') do
    its('RestrictSendingNTLMTraffic') should cmp 2
  end
end


control 'cis-2.3.13.1' do
  impact 1.0
  title 'Ensure Shutdown Allow system to be shut down without having to log on is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.13.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.13.1'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ShutdownWithoutLogon') should cmp 0
  end
end


control 'cis-2.3.15.1' do
  impact 1.0
  title 'Ensure System objects Require case insensitivity for non-Windows subsystems is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.15.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.15.1'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel') do
    its('ObCaseInsensitive') should cmp 1
  end
end


control 'cis-2.3.15.2' do
  impact 1.0
  title 'Ensure System objects Strengthen default permissions of internal system objects e.g. Symbolic Links is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.15.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.15.2'

  describe registry_key('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager') do
    its('ProtectionMode') should cmp 1
  end
end


control 'cis-2.3.17.1' do
  impact 1.0
  title 'Ensure User Account Control Admin Approval Mode for the Built-in Administrator account is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.1. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.1'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('FilterAdministratorToken') should cmp 1
  end
end


control 'cis-2.3.17.2' do
  impact 1.0
  title 'Ensure User Account Control Behavior of the elevation prompt for administrators in Admin Approval Mode\' is set to \'Prompt for consent on the secure desktop or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.2. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.2'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorAdmin') should cmp 2
  end
end


control 'cis-2.3.17.3' do
  impact 1.0
  title 'Ensure User Account Control Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.3. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.3'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('ConsentPromptBehaviorUser') should cmp 0
  end
end


control 'cis-2.3.17.4' do
  impact 1.0
  title 'Ensure User Account Control Detect application installations and prompt for elevation is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.4. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.4'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableInstallerDetection') should cmp 1
  end
end


control 'cis-2.3.17.5' do
  impact 1.0
  title 'Ensure User Account Control Only elevate UIAccess applications that are installed in secure locations is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.5. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.5'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableSecureUIAPaths') should cmp 1
  end
end


control 'cis-2.3.17.6' do
  impact 1.0
  title 'Ensure User Account Control Run all administrators in Admin Approval Mode is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.6. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.6'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableLUA') should cmp 1
  end
end


control 'cis-2.3.17.7' do
  impact 1.0
  title 'Ensure User Account Control Switch to the secure desktop when prompting for elevation is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.7. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.7'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('PromptOnSecureDesktop') should cmp 1
  end
end


control 'cis-2.3.17.8' do
  impact 1.0
  title 'Ensure User Account Control Virtualize file and registry write failures to per-user locations is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.17.8. Generated from Windows-2022-CIS-devel Ansible hardening tasks.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.3.17.8'

  describe registry_key('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('EnableVirtualization') should cmp 1
  end
end
