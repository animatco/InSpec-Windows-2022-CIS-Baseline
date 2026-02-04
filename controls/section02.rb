# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 02 — User Rights Assignment
###############################################
only_if("Section 02 disabled by input") do
  input("run_section_02")
end

#
# 2.2.1 Access Credential Manager as a trusted caller
#
control 'cis-2.2.1' do
  impact 1.0
  title 'Ensure Access Credential Manager as a trusted caller is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.1'

  describe 'Privilege: SeTrustedCredManAccessPrivilege' do
    subject { user_right('SeTrustedCredManAccessPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.2 Access this computer from the network (DC only)
#
control 'cis-2.2.2' do
  impact 1.0
  title 'Ensure Access this computer from the network is set to Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.2'

  describe 'Privilege: SeNetworkLogonRight' do
    subject { user_right('SeNetworkLogonRight').value }
    it { should include 'Administrators' }
    it { should include 'Authenticated Users' }
    it { should include 'ENTERPRISE DOMAIN CONTROLLERS' }
  end
end

#
# 2.2.3 Access this computer from the network (MS only)
#
control 'cis-2.2.3' do
  impact 1.0
  title 'Ensure Access this computer from the network is set to Administrators, Authenticated Users (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.3'

  describe 'Privilege: SeNetworkLogonRight' do
    subject { user_right('SeNetworkLogonRight').value }
    it { should include 'Administrators' }
    it { should include 'Authenticated Users' }
  end
end

#
# 2.2.4 Act as part of the operating system
#
control 'cis-2.2.4' do
  impact 1.0
  title 'Ensure Act as part of the operating system is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.4'

  describe 'Privilege: SeTcbPrivilege' do
    subject { user_right('SeTcbPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.5 Add workstations to domain (DC only)
#
control 'cis-2.2.5' do
  impact 1.0
  title 'Ensure Add workstations to domain is set to Administrators (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.5.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.5'

  describe 'Privilege: SeMachineAccountPrivilege' do
    subject { user_right('SeMachineAccountPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.6 Adjust memory quotas for a process
#
control 'cis-2.2.6' do
  impact 1.0
  title 'Ensure Adjust memory quotas for a process is set to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.6.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.6'

  describe 'Privilege: SeIncreaseQuotaPrivilege' do
    subject { user_right('SeIncreaseQuotaPrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
  end
end

#
# 2.2.7 Allow log on locally (DC only)
#
control 'cis-2.2.7' do
  impact 1.0
  title 'Ensure Allow log on locally is set to Administrators, ENTERPRISE DOMAIN CONTROLLERS (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.7.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.7'

  describe 'Privilege: SeInteractiveLogonRight' do
    subject { user_right('SeInteractiveLogonRight').value }
    it { should include 'Administrators' }
    it { should include 'ENTERPRISE DOMAIN CONTROLLERS' }
  end
end

#
# 2.2.8 Allow log on locally (MS only)
#
control 'cis-2.2.8' do
  impact 1.0
  title 'Ensure Allow log on locally is set to Administrators (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.8.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.8'

  describe 'Privilege: SeInteractiveLogonRight' do
    subject { user_right('SeInteractiveLogonRight').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.9 Allow log on through Remote Desktop Services (DC only)
#
control 'cis-2.2.9' do
  impact 1.0
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.9.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.9'

  describe 'Privilege: SeRemoteInteractiveLogonRight' do
    subject { user_right('SeRemoteInteractiveLogonRight').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.10 Allow log on through Remote Desktop Services (MS only)
#
control 'cis-2.2.10' do
  impact 1.0
  title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.10.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.10'

  describe 'Privilege: SeRemoteInteractiveLogonRight' do
    subject { user_right('SeRemoteInteractiveLogonRight').value }
    it { should include 'Administrators' }
    it { should include 'Remote Desktop Users' }
  end
end

#
# 2.2.11 Back up files and directories
#
control 'cis-2.2.11' do
  impact 1.0
  title 'Ensure Back up files and directories is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.11.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.11'

  describe 'Privilege: SeBackupPrivilege' do
    subject { user_right('SeBackupPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.12 Change the system time
#
control 'cis-2.2.12' do
  impact 1.0
  title 'Ensure Change the system time is set to Administrators, LOCAL SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.12.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.12'

  describe 'Privilege: SeSystemTimePrivilege' do
    subject { user_right('SeSystemTimePrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
  end
end

#
# 2.2.13 Change the time zone
#
control 'cis-2.2.13' do
  impact 1.0
  title 'Ensure Change the time zone is set to Administrators, LOCAL SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.13.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.13'

  describe 'Privilege: SeTimeZonePrivilege' do
    subject { user_right('SeTimeZonePrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
  end
end

#
# 2.2.14 Create a pagefile
#
control 'cis-2.2.14' do
  impact 1.0
  title 'Ensure Create a pagefile is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.14.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.14'

  describe 'Privilege: SeCreatePagefilePrivilege' do
    subject { user_right('SeCreatePagefilePrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.15 Create a token object
#
control 'cis-2.2.15' do
  impact 1.0
  title 'Ensure Create a token object is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.15.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.15'

  describe 'Privilege: SeCreateTokenPrivilege' do
    subject { user_right('SeCreateTokenPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.16 Create global objects
#
control 'cis-2.2.16' do
  impact 1.0
  title 'Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.16.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.16'

  describe 'Privilege: SeCreateGlobalPrivilege' do
    subject { user_right('SeCreateGlobalPrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

#
# 2.2.17 Create permanent shared objects
#
control 'cis-2.2.17' do
  impact 1.0
  title 'Ensure Create permanent shared objects is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.17.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.17'

  describe 'Privilege: SeCreatePermanentPrivilege' do
    subject { user_right('SeCreatePermanentPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.18 Create symbolic links (DC only)
#
control 'cis-2.2.18' do
  impact 1.0
  title 'Ensure Create symbolic links is set to Administrators (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.18.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.18'

  describe 'Privilege: SeCreateSymbolicLinkPrivilege' do
    subject { user_right('SeCreateSymbolicLinkPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.19 Create symbolic links (MS only)
#
control 'cis-2.2.19' do
  impact 1.0
  title 'Ensure Create symbolic links is set to Administrators (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.19.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.19'

  describe 'Privilege: SeCreateSymbolicLinkPrivilege' do
    subject { user_right('SeCreateSymbolicLinkPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.20 Debug programs
#
control 'cis-2.2.20' do
  impact 1.0
  title 'Ensure Debug programs is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.20.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.20'

  describe 'Privilege: SeDebugPrivilege' do
    subject { user_right('SeDebugPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.21 Deny access to this computer from the network (DC only)
#
control 'cis-2.2.21' do
  impact 1.0
  title 'Ensure Deny access to this computer from the network includes Guests (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.21.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.21'

  describe 'Privilege: SeDenyNetworkLogonRight' do
    subject { user_right('SeDenyNetworkLogonRight').value }
    it { should include 'Guests' }
  end
end

#
# 2.2.22 Deny access to this computer from the network (MS only)
#
control 'cis-2.2.22' do
  impact 1.0
  title 'Ensure Deny access to this computer from the network includes Guests, Local Account, Administrators (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.22.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.22'

  describe 'Privilege: SeDenyNetworkLogonRight' do
    subject { user_right('SeDenyNetworkLogonRight').value }
    it { should include 'Guests' }
    it { should include 'Local Account' }
    it { should include 'Administrators' }
  end
end

#
# 2.2.23 Deny log on as a batch job
#
control 'cis-2.2.23' do
  impact 1.0
  title 'Ensure Deny log on as a batch job includes Guests'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.23.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.23'

  describe 'Privilege: SeDenyBatchLogonRight' do
    subject { user_right('SeDenyBatchLogonRight').value }
    it { should include 'Guests' }
  end
end

#
# 2.2.24 Deny log on as a service
#
control 'cis-2.2.24' do
  impact 1.0
  title 'Ensure Deny log on as a service includes Guests'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.24.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.24'

  describe 'Privilege: SeDenyServiceLogonRight' do
    subject { user_right('SeDenyServiceLogonRight').value }
    it { should include 'Guests' }
  end
end

#
# 2.2.25 Deny log on locally
#
control 'cis-2.2.25' do
  impact 1.0
  title 'Ensure Deny log on locally includes Guests'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.25.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.25'

  describe 'Privilege: SeDenyInteractiveLogonRight' do
    subject { user_right('SeDenyInteractiveLogonRight').value }
    it { should include 'Guests' }
  end
end

#
# 2.2.26 Deny log on through Remote Desktop Services (DC only)
#
control 'cis-2.2.26' do
  impact 1.0
  title 'Ensure Deny log on through Remote Desktop Services includes Guests (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.26.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.26'

  describe 'Privilege: SeDenyRemoteInteractiveLogonRight' do
    subject { user_right('SeDenyRemoteInteractiveLogonRight').value }
    it { should include 'Guests' }
  end
end

#
# 2.2.27 Deny log on through Remote Desktop Services (MS only)
#
control 'cis-2.2.27' do
  impact 1.0
  title 'Ensure Deny log on through Remote Desktop Services includes Guests, Local Account (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.27.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.27'

  describe 'Privilege: SeDenyRemoteInteractiveLogonRight' do
    subject { user_right('SeDenyRemoteInteractiveLogonRight').value }
    it { should include 'Guests' }
    it { should include 'Local Account' }
  end
end

#
# 2.2.28 Enable computer and user accounts to be trusted for delegation (DC only)
#
control 'cis-2.2.28' do
  impact 1.0
  title 'Ensure Enable computer and user accounts to be trusted for delegation is set to Administrators (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.28.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.28'

  describe 'Privilege: SeEnableDelegationPrivilege' do
    subject { user_right('SeEnableDelegationPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.29 Enable computer and user accounts to be trusted for delegation (MS only)
#
control 'cis-2.2.29' do
  impact 1.0
  title 'Ensure Enable computer and user accounts to be trusted for delegation is set to No One (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.29.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.29'

  describe 'Privilege: SeEnableDelegationPrivilege' do
    subject { user_right('SeEnableDelegationPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.30 Force shutdown from a remote system
#
control 'cis-2.2.30' do
  impact 1.0
  title 'Ensure Force shutdown from a remote system is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.30.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.30'

  describe 'Privilege: SeRemoteShutdownPrivilege' do
    subject { user_right('SeRemoteShutdownPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.31 Generate security audits
#
control 'cis-2.2.31' do
  impact 1.0
  title 'Ensure Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.31.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.31'

  describe 'Privilege: SeAuditPrivilege' do
    subject { user_right('SeAuditPrivilege').value }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
  end
end

#
# 2.2.32 Impersonate a client after authentication (DC only)
#
control 'cis-2.2.32' do
  impact 1.0
  title 'Ensure Impersonate a client after authentication is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.32.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.2.32'

  describe 'Privilege: SeImpersonatePrivilege' do
    subject { user_right('SeImpersonatePrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

#
# 2.2.33 Impersonate a client after authentication (MS only)
#
control 'cis-2.2.33' do
  impact 1.0
  title 'Ensure Impersonate a client after authentication is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE (MS only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.33.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Member Server controls disabled') { input('server_role') == 'member_server' }

  tag cis_id: '2.2.33'

  describe 'Privilege: SeImpersonatePrivilege' do
    subject { user_right('SeImpersonatePrivilege').value }
    it { should include 'Administrators' }
    it { should include 'LOCAL SERVICE' }
    it { should include 'NETWORK SERVICE' }
    it { should include 'SERVICE' }
  end
end

#
# 2.2.34 Increase scheduling priority
#
control 'cis-2.2.34' do
  impact 1.0
  title 'Ensure Increase scheduling priority is set to Administrators, Window Manager\Window Manager Group'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.34.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.34'

  describe 'Privilege: SeIncreaseBasePriorityPrivilege' do
    subject { user_right('SeIncreaseBasePriorityPrivilege').value }
    it { should include 'Administrators' }
    it { should include 'Window Manager\\Window Manager Group' }
  end
end

#
# 2.2.35 Load and unload device drivers
#
control 'cis-2.2.35' do
  impact 1.0
  title 'Ensure Load and unload device drivers is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.35.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.35'

  describe 'Privilege: SeLoadDriverPrivilege' do
    subject { user_right('SeLoadDriverPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.36 Lock pages in memory
#
control 'cis-2.2.36' do
  impact 1.0
  title 'Ensure Lock pages in memory is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.36.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.36'

  describe 'Privilege: SeLockMemoryPrivilege' do
    subject { user_right('SeLockMemoryPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.2.37 Log on as a batch job
#
control 'cis-2.2.37' do
  impact 1.0
  title 'Ensure Log on as a batch job is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.37.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.37'

  describe 'Privilege: SeBatchLogonRight' do
    subject { user_right('SeBatchLogonRight').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.38 Log on as a service
#
control 'cis-2.2.38' do
  impact 1.0
  title 'Ensure Log on as a service is set to No One (unless required by service accounts)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.38.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.38'

  describe 'Privilege: SeServiceLogonRight' do
    subject { user_right('SeServiceLogonRight').value }
    it { should eq [] }
  end
end

#
# 2.2.39 Manage auditing and security log
#
control 'cis-2.2.39' do
  impact 1.0
  title 'Ensure Manage auditing and security log is set to Administrators'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.39.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.39'

  describe 'Privilege: SeSecurityPrivilege' do
    subject { user_right('SeSecurityPrivilege').value }
    it { should include 'Administrators' }
  end
end

#
# 2.2.40 Modify an object label
#
control 'cis-2.2.40' do
  impact 1.0
  title 'Ensure Modify an object label is set to No One'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.2.40.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '2.2.40'

  describe 'Privilege: SeReLabelPrivilege' do
    subject { user_right('SeReLabelPrivilege').value }
    it { should eq [] }
  end
end

#
# 2.3.1 Audit Account Logon Events
#
control 'cis-2.3.1' do
  impact 1.0
  title 'Ensure Audit Account Logon is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.1'

  describe 'Audit Policy: Account Logon' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Account Logon'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.2 Audit Account Management
#
control 'cis-2.3.2' do
  impact 1.0
  title 'Ensure Audit Account Management is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.2'

  describe 'Audit Policy: Account Management' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Account Management'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.3 Audit Directory Service Access (DC only)
#
control 'cis-2.3.3' do
  impact 1.0
  title 'Ensure Audit Directory Service Access is set to Success and Failure (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.3'

  describe 'Audit Policy: Directory Service Access' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Directory Service Access'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.4 Audit Logon Events
#
control 'cis-2.3.4' do
  impact 1.0
  title 'Ensure Audit Logon is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.4'

  describe 'Audit Policy: Logon' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Logon'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.5 Audit Object Access
#
control 'cis-2.3.5' do
  impact 1.0
  title 'Ensure Audit Object Access is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.5.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.5'

  describe 'Audit Policy: Object Access' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Object Access'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.6 Audit Policy Change
#
control 'cis-2.3.6' do
  impact 1.0
  title 'Ensure Audit Policy Change is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.6'

  describe 'Audit Policy: Policy Change' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Policy Change'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.7 Audit Privilege Use
#
control 'cis-2.3.7' do
  impact 1.0
  title 'Ensure Audit Privilege Use is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.7'

  describe 'Audit Policy: Privilege Use' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Privilege Use'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.8 Audit Process Tracking
#
control 'cis-2.3.8' do
  impact 1.0
  title 'Ensure Audit Process Tracking is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.8.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.8'

  describe 'Audit Policy: Process Tracking' do
    subject { CisAuditPolicy.expected?(audit_policy.category('Process Tracking'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.9 Audit System Events
#
control 'cis-2.3.9' do
  impact 1.0
  title 'Ensure Audit System Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.9'

  describe 'Audit Policy: System' do
    subject { CisAuditPolicy.expected?(audit_policy.category('System'), %w[Success Failure]) }
    it { should cmp true }
  end
end

#
# 2.3.1.1 Accounts: Administrator account status
#
control 'cis-2.3.1.1' do
  impact 1.0
  title 'Ensure Accounts: Administrator account status is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.1.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.1.1'

  describe 'Security Option: Administrator account status' do
    subject { CisSecurityOptions.disabled?(local_security_policy.EnableAdminAccount) }
    it { should cmp true }
  end
end

#
# 2.3.1.2 Accounts: Guest account status
#
control 'cis-2.3.1.2' do
  impact 1.0
  title 'Ensure Accounts: Guest account status is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.1.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.1.2'

  describe 'Security Option: Guest account status' do
    subject { CisSecurityOptions.disabled?(local_security_policy.EnableGuestAccount) }
    it { should cmp true }
  end
end

#
# 2.3.1.3 Accounts: Limit local account use of blank passwords
#
control 'cis-2.3.1.3' do
  impact 1.0
  title 'Ensure Accounts: Limit local account use of blank passwords to console logon only is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.1.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.1.3'

  describe 'Security Option: Limit blank passwords' do
    subject { CisSecurityOptions.enabled?(local_security_policy.LimitBlankPasswordUse) }
    it { should cmp true }
  end
end

#
# 2.3.2.1 Audit: Force audit policy subcategory settings
#
control 'cis-2.3.2.1' do
  impact 1.0
  title 'Ensure Audit: Force audit policy subcategory settings is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.2.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.2.1'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa') do
    its('SCENoApplyLegacyAuditPolicy') { should cmp 1 }
  end
end

#
# 2.3.4.1 Devices: Prevent users from installing printer drivers
#
control 'cis-2.3.4.1' do
  impact 1.0
  title 'Ensure Devices: Prevent users from installing printer drivers is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.4.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.4.1'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers') do
    its('AddPrinterDrivers') { should cmp 1 }
  end
end

#
# 2.3.6.1 Domain controller: Allow server operators to schedule tasks (DC only)
#
control 'cis-2.3.6.1' do
  impact 1.0
  title 'Ensure Domain controller: Allow server operators to schedule tasks is Disabled (DC only)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.6.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Domain Controller controls disabled') { input('server_role') == 'domain_controller' }

  tag cis_id: '2.3.6.1'

  describe 'Security Option: Allow server operators to schedule tasks' do
    subject { CisSecurityOptions.disabled?(local_security_policy.EnableServerOperatorsScheduleTasks) }
    it { should cmp true }
  end
end

#
# 2.3.7.1 Domain member: Digitally encrypt or sign secure channel data
#
control 'cis-2.3.7.1' do
  impact 1.0
  title 'Ensure Domain member: Digitally encrypt or sign secure channel data is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.7.1'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireSignOrSeal') { should cmp 1 }
  end
end

#
# 2.3.7.2 Domain member: Digitally encrypt secure channel data
#
control 'cis-2.3.7.2' do
  impact 1.0
  title 'Ensure Domain member: Digitally encrypt secure channel data is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.7.2'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SealSecureChannel') { should cmp 1 }
  end
end

#
# 2.3.7.3 Domain member: Digitally sign secure channel data
#
control 'cis-2.3.7.3' do
  impact 1.0
  title 'Ensure Domain member: Digitally sign secure channel data is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.7.3'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('SignSecureChannel') { should cmp 1 }
  end
end

#
# 2.3.7.4 Domain member: Require strong session key
#
control 'cis-2.3.7.4' do
  impact 1.0
  title 'Ensure Domain member: Require strong session key is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.7.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.7.4'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    its('RequireStrongKey') { should cmp 1 }
  end
end

#
# 2.3.8.1 Interactive logon: Do not require CTRL+ALT+DEL
#
control 'cis-2.3.8.1' do
  impact 1.0
  title 'Ensure Interactive logon: Do not require CTRL+ALT+DEL is Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.8.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.8.1'

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('DisableCAD') { should cmp 0 }
  end
end

#
# 2.3.8.2 Interactive logon: Machine inactivity limit
#
control 'cis-2.3.8.2' do
  impact 1.0
  title 'Ensure Interactive logon: Machine inactivity limit is set to 900 seconds or fewer'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.8.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.8.2'

  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    its('InactivityTimeoutSecs') { should cmp <= 900 }
  end
end

#
# 2.3.9.1 Microsoft network client: Digitally sign communications (always)
#
control 'cis-2.3.9.1' do
  impact 1.0
  title 'Ensure Microsoft network client: Digitally sign communications (always) is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.9.1'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

#
# 2.3.9.2 Microsoft network client: Digitally sign communications (if server agrees)
#
control 'cis-2.3.9.2' do
  impact 1.0
  title 'Ensure Microsoft network client: Digitally sign communications (if server agrees) is Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 2.3.9.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }

  tag cis_id: '2.3.9.2'

  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters') do
    its('EnableSecuritySignature') { should cmp 1 }
  end
end
