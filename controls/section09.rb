# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 09 — Windows Firewall with Advanced Security
###############################################
only_if("Section 09 disabled by input") do
  input("run_section_09")
end


control 'cis-9.1.1' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windowsfirewall\\Domainprofile') do
    its('EnableFirewall') { should cmp 1 }
  end
end

control 'cis-9.1.2' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    its('DefaultInboundAction') { should cmp 1 }
  end
end

control 'cis-9.1.3' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile') do
    its('DisableNotifications') { should cmp 1 }
  end
end

control 'cis-9.1.4' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%/System32/logfiles/firewall/domainfw.log'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogFilePath') { should eq '%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log' }
  end
end

control 'cis-9.1.5' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogFileSize') { should cmp 16384 }
  end
end

control 'cis-9.1.6' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogDroppedPackets') { should cmp 1 }
  end
end

control 'cis-9.1.7' do
  impact 1.0
  title "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.1.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.1.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp 1 }
  end
end

control 'cis-9.2.1' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('EnableFirewall') { should cmp 1 }
  end
end

control 'cis-9.2.2' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('DefaultInboundAction') { should cmp 1 }
  end
end

control 'cis-9.2.3' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile') do
    its('DisableNotifications') { should cmp 1 }
  end
end

control 'cis-9.2.4' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%/System32/logfiles/firewall/privatefw.log'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogFilePath') { should eq '%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log' }
  end
end

control 'cis-9.2.5' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogFileSize') { should cmp 16384 }
  end
end

control 'cis-9.2.6' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogDroppedPackets') { should cmp 1 }
  end
end

control 'cis-9.2.7' do
  impact 1.0
  title "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.2.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.2.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp 1 }
  end
end

control 'cis-9.3.1' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.1.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.1'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('EnableFirewall') { should cmp 1 }
  end
end

control 'cis-9.3.2' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.2.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.2'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('DefaultInboundAction') { should cmp 1 }
  end
end

control 'cis-9.3.3' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.3.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.3'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('DisableNotifications') { should cmp 1 }
  end
end

control 'cis-9.3.4' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.4.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.4'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('AllowLocalPolicyMerge') { should cmp 0 }
  end
end

control 'cis-9.3.5' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.5.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.5'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile') do
    its('AllowLocalIPsecPolicyMerge') { should cmp 0 }
  end
end

control 'cis-9.3.6' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%/System32/logfiles/firewall/publicfw.log'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.6.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.6'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogFilePath') { should eq '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log' }
  end
end

control 'cis-9.3.7' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.7.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.7'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogFileSize') { should cmp 16384 }
  end
end

control 'cis-9.3.8' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.8.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.8'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogDroppedPackets') { should cmp 1 }
  end
end

control 'cis-9.3.9' do
  impact 1.0
  title "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 9.3.9.'
  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role mismatch') { input('server_role') == 'domain_controller' || input('server_role') == 'member_server' }
  tag cis_id: '9.3.9'
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging') do
    its('LogSuccessfulConnections') { should cmp 1 }
  end
end
