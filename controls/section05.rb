# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 05 — System Services
###############################################
only_if("Section 05 disabled by input") do
  input("run_section_05")
end

control 'cis-5.1' do
  impact 1.0
  title 'Ensure Print Spooler (Spooler) is set to Disabled Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 5.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Domain Controller role required') { input('server_role') == 'domain_controller' }
  tag cis_id: '5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler') do
    its('Start') { should cmp 4 }
  end
end

control 'cis-5.2' do
  impact 1.0
  title 'Ensure Print Spooler (Spooler) is set to Disabled Member Server'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 5.2.'
  only_if('Level 2 controls enabled') { input('run_level_1') }
  only_if('Member Server role required') { input('server_role') == 'member_server' }
  tag cis_id: '5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler') do
    its('Start') { should cmp 4 }
  end
end
