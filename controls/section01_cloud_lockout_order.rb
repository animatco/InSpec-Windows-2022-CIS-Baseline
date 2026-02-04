# frozen_string_literal: true

###############################################
# CIS Microsoft Windows Server 2022 Benchmark
# Section 01 — Account Policies (cloud lockout ordering)
###############################################

only_if('Section 01 enabled by input') do
  input('run_section_01')
end

# 1.2.2 Account lockout threshold

control 'cis-1.2.2' do
  impact 1.0
  title "Ensure Account lockout threshold is set to #{input('account_lockout_threshold')} or fewer invalid logon attempt(s), but not 0."
  desc  'CIS Microsoft Windows Server 2022 control 1.2.2 (cloud ordering variant).'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end

  tag cis_id: '1.2.2'

  describe 'Lockout threshold' do
    subject { CisPasswordPolicy.lockout_threshold(local_security_policy.LockoutBadCount) }

    it { should_not be_nil }
    it { should cmp <= input('account_lockout_threshold') }
    it { should_not cmp 0 }
  end
end

# 1.2.1 Account lockout duration

control 'cis-1.2.1' do
  impact 1.0
  title "Ensure Account lockout duration is set to #{input('account_lockout_duration_minutes')} or more minutes"
  desc  'CIS Microsoft Windows Server 2022 control 1.2.1 (cloud ordering variant).'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end

  tag cis_id: '1.2.1'

  describe 'Lockout duration (minutes)' do
    subject { CisPasswordPolicy.lockout_minutes(local_security_policy.LockoutDuration) }

    it { should_not be_nil }
    it { should cmp >= input('account_lockout_duration_minutes') }
  end
end

# 1.2.3 Allow Administrator account lockout

control 'cis-1.2.3' do
  impact 1.0
  title 'Ensure Allow Administrator account lockout is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 control 1.2.3 (cloud ordering variant).'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end

  tag cis_id: '1.2.3'

  # Read AllowAdministratorLockout directly from secedit [System Access]
  raw_admin_lockout = powershell(<<~POWERSHELL).stdout.to_s.strip
    $cfg = 'C:\\Windows\\Temp\\cis-secpol-1-2-3-cloud.cfg'
    secedit /export /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
    if (Test-Path $cfg) {
      $line = Get-Content $cfg |
        Where-Object { $_ -match '^\\s*AllowAdministratorLockout\\s*=' } |
        Select-Object -First 1
      if ($line) {
        ($line -split '=', 2)[1].Trim()
      }
    }
  POWERSHELL

  describe 'Administrator lockout enabled' do
    subject { CisPasswordPolicy.admin_lockout_enabled?(raw_admin_lockout) }

    it { should_not be_nil }
    it { should cmp true }
  end
end

# 1.2.4 Reset account lockout counter

control 'cis-1.2.4' do
  impact 1.0
  title "Ensure Reset account lockout counter after is set to #{input('reset_account_lockout_counter_minutes')} or more minutes."
  desc  'CIS Microsoft Windows Server 2022 control 1.2.4 (cloud ordering variant).'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end

  tag cis_id: '1.2.4'

  describe 'Reset lockout counter (minutes)' do
    subject { CisPasswordPolicy.reset_lockout_minutes(local_security_policy.ResetLockoutCount) }

    it { should_not be_nil }
    it { should cmp >= input('reset_account_lockout_counter_minutes') }
  end
end
