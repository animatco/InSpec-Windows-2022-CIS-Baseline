# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 01 — Account Policies
###############################################
only_if("Section 01 disabled by input") do
  input("run_section_01")
end

#
# 1.2.2 Account lockout threshold
#
control 'cis-1.2.2' do
  impact 1.0
  title 'Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 1.2.2.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.2'

  describe 'Lockout threshold' do
    subject { CisPasswordPolicy.lockout_threshold(local_security_policy.LockoutBadCount) }
    it { should cmp <= 5 }
    it { should_not cmp 0 }
  end
end

#
# 1.2.1 Account lockout duration
#
control 'cis-1.2.1' do
  impact 1.0
  title 'Ensure Account lockout duration is set to 15 or more minutes'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 1.2.1.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.1'

  describe 'Lockout duration (minutes)' do
    subject { CisPasswordPolicy.lockout_minutes(local_security_policy.LockoutDuration) }
    it { should cmp >= 15 }
  end
end

#
# 1.2.3 Allow Administrator account lockout
#
control 'cis-1.2.3' do
  impact 1.0
  title 'Ensure Allow Administrator account lockout is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 1.2.3.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Not a member server') { input('server_role') == 'member_server' }

  tag cis_id: '1.2.3'

  describe 'Administrator lockout enabled' do
    subject { CisPasswordPolicy.admin_lockout_enabled?(local_security_policy.AllowAdministratorLockout) }
    it { should cmp true }
  end
end

#
# 1.2.4 Reset account lockout counter
#
control 'cis-1.2.4' do
  impact 1.0
  title 'Ensure Reset account lockout counter after is set to 15 or more minutes.'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 1.2.4.'

  only_if('Level 1 controls disabled') { input('run_level_1') }
  only_if('Server role not DC or member server') { %w[domain_controller member_server].include?(input('server_role')) }

  tag cis_id: '1.2.4'

  describe 'Reset lockout counter (minutes)' do
    subject { CisPasswordPolicy.reset_lockout_minutes(local_security_policy.ResetLockoutCount) }
    it { should cmp >= 15 }
  end
end
