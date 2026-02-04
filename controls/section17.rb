# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 17 — Advanced Audit Policy Configuration
###############################################
only_if("Section 17 disabled by input") do
  input("run_section_17")
end

control 'cis-17.1.1' do
  impact 1.0
  title 'Ensure Audit Credential Validation is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.1.1'
  describe auditpol_subcategory('{0cce923f-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.1.2' do
  impact 1.0
  title "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure' DC Only | Domain Controller"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.1.2'
  describe auditpol_subcategory('{0cce9242-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.1.3' do
  impact 1.0
  title "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure' DC Only"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.1.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.1.3'
  describe auditpol_subcategory('{0cce9240-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.2.1' do
  impact 1.0
  title 'Ensure Audit Application Group Management is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.2.1'
  describe auditpol_subcategory('{0cce9239-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.2.2' do
  impact 1.0
  title 'Ensure Audit Computer Account Management is set to include Success DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.2.2'
  describe auditpol_subcategory('{0cce9236-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.2.3' do
  impact 1.0
  title 'Ensure Audit Distribution Group Management is set to include Success DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.2.3'
  describe auditpol_subcategory('{0cce9238-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.2.4' do
  impact 1.0
  title 'Ensure Audit Other Account Management Events is set to include Success DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.2.4'
  describe auditpol_subcategory('{0cce923a-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.2.5' do
  impact 1.0
  title 'Ensure Audit Security Group Management is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.2.5'
  describe auditpol_subcategory('{0cce9237-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.2.6' do
  impact 1.0
  title 'Ensure Audit User Account Management is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.2.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.2.6'
  describe auditpol_subcategory('{0cce9235-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.3.1' do
  impact 1.0
  title 'Ensure Audit PNP Activity is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.3.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.3.1'
  describe auditpol_subcategory('{0cce9248-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.3.2' do
  impact 1.0
  title 'Ensure Audit Process Creation is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.3.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.3.2'
  describe auditpol_subcategory('{0cce922b-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.3.3' do
  impact 1.0
  title 'Ensure Audit Other Detailed Tracking Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.3.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.3.3'
  describe auditpol_subcategory('{0cce922e-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.4.1' do
  impact 1.0
  title 'Ensure Audit Directory Service Access is set to include Failure DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.4.1'
  describe auditpol_subcategory('{0cce923b-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.4.2' do
  impact 1.0
  title 'Ensure Audit Directory Service Changes is set to include Success DC only | Domain Controller'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '17.4.2'
  describe auditpol_subcategory('{0cce923c-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.5.1' do
  impact 1.0
  title 'Ensure Audit Account Lockout is set to include Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.1'
  describe auditpol_subcategory('{0cce9217-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.5.2' do
  impact 1.0
  title 'Ensure Audit Group Membership is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.2'
  describe auditpol_subcategory('{0cce9249-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.5.3' do
  impact 1.0
  title 'Ensure Audit Logoff is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.3'
  describe auditpol_subcategory('{0cce9216-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.5.4' do
  impact 1.0
  title 'Ensure Audit Logon is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.4'
  describe auditpol_subcategory('{0cce9215-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.5.5' do
  impact 1.0
  title 'Ensure Audit Other Logon,Logoff Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.5'
  describe auditpol_subcategory('{0cce921c-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.5.6' do
  impact 1.0
  title 'Ensure Audit Special Logon is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.5.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.5.6'
  describe auditpol_subcategory('{0cce921b-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.6.1' do
  impact 1.0
  title 'Ensure Audit Detailed File Share is set to include Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.6.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.6.1'
  describe auditpol_subcategory('{0cce9244-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.6.2' do
  impact 1.0
  title 'Ensure Audit File Share is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.6.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.6.2'
  describe auditpol_subcategory('{0cce9224-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.6.3' do
  impact 1.0
  title 'Ensure Audit Other Object Access Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.6.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.6.3'
  describe auditpol_subcategory('{0cce9227-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.6.4' do
  impact 1.0
  title 'Ensure Audit Removable Storage is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.6.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.6.4'
  describe auditpol_subcategory('{0cce9245-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.6.5' do
  impact 1.0
  title 'Ensure Audit SAM is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.6.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.6.5'
  describe auditpol_subcategory('{0cce9246-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.7.1' do
  impact 1.0
  title 'Ensure Audit Audit Policy Change is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.7.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.7.1'
  describe auditpol_subcategory('{0cce922f-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.7.2' do
  impact 1.0
  title 'Ensure Audit Authentication Policy Change is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.7.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.7.2'
  describe auditpol_subcategory('{0cce9230-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.7.3' do
  impact 1.0
  title 'Ensure Audit Authorization Policy Change is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.7.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.7.3'
  describe auditpol_subcategory('{0cce9231-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.7.4' do
  impact 1.0
  title 'Ensure Audit MPSSVC Rule-Level Policy Change is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.7.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.7.4'
  describe auditpol_subcategory('{0cce9232-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.7.5' do
  impact 1.0
  title 'Ensure Audit Other Policy Change Events is set to include Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.7.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.7.5'
  describe auditpol_subcategory('{0cce9234-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.8.1' do
  impact 1.0
  title 'Ensure Audit Sensitive Privilege Use is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.8.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.8.1'
  describe auditpol_subcategory('{0cce9228-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.8.2' do
  impact 1.0
  title 'Ensure Audit Non Sensitive Privilege Use is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.8.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.8.2'
  describe auditpol_subcategory('{0cce9229-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.9.1' do
  impact 1.0
  title 'Ensure Audit IPsec Driver is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.9.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.9.1'
  describe auditpol_subcategory('{0cce9213-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.9.2' do
  impact 1.0
  title 'Ensure Audit Other System Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.9.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.9.2'
  describe auditpol_subcategory('{0cce9214-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.9.3' do
  impact 1.0
  title 'Ensure Audit Security State Change is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.9.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.9.3'
  describe auditpol_subcategory('{0cce9210-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.9.4' do
  impact 1.0
  title 'Ensure Audit Security System Extension is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.9.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.9.4'
  describe auditpol_subcategory('{0cce9211-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.9.5' do
  impact 1.0
  title 'Ensure Audit System Integrity is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.9.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.9.5'
  describe auditpol_subcategory('{0cce9212-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.10.1' do
  impact 1.0
  title 'Ensure Audit Filtering Platform Connection is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.10.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.10.1'
  describe auditpol_subcategory('{0cce9226-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.10.2' do
  impact 1.0
  title 'Ensure Audit Filtering Platform Packet Drop is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.10.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.10.2'
  describe auditpol_subcategory('{0cce9225-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.10.3' do
  impact 1.0
  title 'Ensure Audit Other Filtering Platform Events is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.10.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.10.3'
  describe auditpol_subcategory('{0cce9241-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.11.1' do
  impact 1.0
  title 'Ensure Audit Certification Services is set to Success and Failure'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.11.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.11.1'
  describe auditpol_subcategory('{0cce9247-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'Success' }
  end
end

control 'cis-17.11.2' do
  impact 1.0
  title 'Ensure Audit Other Object Access Events is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.11.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.11.2'
  describe auditpol_subcategory('{0cce9243-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.12.1' do
  impact 1.0
  title 'Ensure Audit Registry is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.12.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.12.1'
  describe auditpol_subcategory('{0cce9242-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.13.1' do
  impact 1.0
  title 'Ensure Audit File System is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.13.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.13.1'
  describe auditpol_subcategory('{0cce9223-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.14.1' do
  impact 1.0
  title 'Ensure Audit Kernel Object is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.14.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.14.1'
  describe auditpol_subcategory('{0cce921d-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end

control 'cis-17.15.1' do
  impact 1.0
  title 'Ensure Audit Handle Manipulation is set to include Success'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 17.15.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '17.15.1'
  describe auditpol_subcategory('{0cce921e-69ae-11d9-bed3-505054503030}') do
    its('inclusion_setting') { should cmp 'include' }
  end
end
