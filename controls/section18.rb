# frozen_string_literal: true
###############################################
#  CIS Microsoft Windows Server 2022 Benchmark
#  Section 18 — Administrative Templates (Computer)
###############################################
only_if("Section 18 disabled by input") do
  input("run_section_18")
end

control 'cis-18.1.1.1' do
  impact 1.0
  title 'Ensure Prevent enabling lock screen camera is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.1.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.1.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenCamera') { should cmp 1 }
  end
end

control 'cis-18.1.1.2' do
  impact 1.0
  title 'Ensure Prevent enabling lock screen slide show is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.1.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.1.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
    its('NoLockScreenSlideshow') { should cmp 1 }
  end
end

control 'cis-18.1.2.2' do
  impact 1.0
  title 'Ensure Allow users to enable online speech recognition services is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.1.2.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.1.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization') do
    its('AllowInputPersonalization') { should cmp 0 }
  end
end

control 'cis-18.1.3' do
  impact 1.0
  title 'Ensure Allow Online Tips is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.1.3.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.1.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('AllowOnlineTips') { should cmp 0 }
  end
end

control 'cis-18.4.1' do
  impact 1.0
  title 'Ensure Apply UAC restrictions to local accounts on network logons is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('LocalAccountTokenFilterPolicy') { should cmp 0 }
  end
end

control 'cis-18.4.2' do
  impact 1.0
  title 'Ensure Configure SMB v1 client driver is set to Enabled: Disable driver (recommended)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10') do
    its('Start') { should cmp 4 }
  end
end

control 'cis-18.4.3' do
  impact 1.0
  title 'Ensure Configure SMB v1 server is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.4.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') do
    its('SMB1') { should cmp 0 }
  end
end

control 'cis-18.4.4' do
  impact 1.0
  title 'Ensure Enable Certificate Padding is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.4.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Wintrust\Config') do
    its('EnableCertPaddingCheck') { should cmp 1 }
  end
end

control 'cis-18.4.5' do
  impact 1.0
  title 'Ensure Enable Structured Exception Handling Overwrite Protection (SEHOP) is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.4.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel') do
    its('DisableExceptionChainValidation') { should cmp 0 }
  end
end

control 'cis-18.4.6' do
  impact 1.0
  title "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.4.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters') do
    its('NodeType') { should cmp 2 }
  end
end

control 'cis-18.4.7' do
  impact 1.0
  title 'Ensure WDigest Authentication is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.4.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.4.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest') do
    its('UseLogonCredential') { should cmp 0 }
  end
end

control 'cis-18.5.1' do
  impact 1.0
  title 'Ensure MSS: (AutoAdminLogon) Enable Automatic Logon is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('AutoAdminLogon') { should cmp 0 }
  end
end

control 'cis-18.5.2' do
  impact 1.0
  title 'Ensure MSS: (DisableIPSourceRouting IPv6) IP source routing protection level is set to Enabled: Highest protection, source routing is completely disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end

control 'cis-18.5.3' do
  impact 1.0
  title 'Ensure MSS: (DisableIPSourceRouting) IP source routing protection level is set to Enabled: Highest protection, source routing is completely disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.5.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end

control 'cis-18.5.4' do
  impact 1.0
  title 'Ensure MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.5.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    its('EnableICMPRedirect') { should cmp 0 }
  end
end

control 'cis-18.5.5' do
  impact 1.0
  title 'Ensure MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds is set to Enabled: 300,000 or 5 minutes'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.5.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.5'
  
  if registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters').exist?
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
      its('KeepAliveTime') { should cmp 300000 }
    end
  else
    describe 'KeepAliveTime Registry Setting' do
      skip 'Registry key does not exist - policy not configured'
    end
  end
end

control 'cis-18.5.6' do
  impact 1.0
  title 'Ensure MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters') do
    its('NoNameReleaseOnDemand') { should cmp 1 }
  end
end

control 'cis-18.5.7' do
  impact 1.0
  title 'Ensure MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.7.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    its('PerformRouterDiscovery') { should cmp 0 }
  end
end

control 'cis-18.5.8' do
  impact 1.0
  title 'Ensure MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.8.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager') do
    its('SafeDllSearchMode') { should cmp 1 }
  end
end

control 'cis-18.5.9' do
  impact 1.0
  title 'Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires is set to Enabled: 5 or fewer seconds'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.9.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.9'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    its('ScreenSaverGracePeriod') { should cmp 5 }
  end
end

control 'cis-18.5.10' do
  impact 1.0
  title 'Ensure MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted is set to Enabled: 3'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.10.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.10'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp 3 }
  end
end

control 'cis-18.5.11' do
  impact 1.0
  title 'Ensure MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted is set to Enabled: 3'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.11.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.11'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
    its('TcpMaxDataRetransmissions') { should cmp 3 }
  end
end

control 'cis-18.5.12' do
  impact 1.0
  title 'Ensure MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning is set to Enabled: 90 or less'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.5.12.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.5.12'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security') do
    its('WarningLevel') { should cmp 90 }
  end
end

control 'cis-18.6.4.1' do
  impact 1.0
  title 'Ensure Configure multicast DNS (mDNS) protocol is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') do
    its('EnableMDNS') { should cmp 0 }
  end
end

control 'cis-18.6.4.2' do
  impact 1.0
  title "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') do
    its('EnableNetbios') { should cmp 2 }
  end
end

control 'cis-18.6.4.3' do
  impact 1.0
  title "Ensure 'Turn off default IPv6 DNS Servers' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.4.3.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.4.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') do
    its('DisableIPv6DefaultDnsServers') { should cmp 1 }
  end
end

control 'cis-18.6.4.4' do
  impact 1.0
  title 'Ensure Turn off multicast name resolution is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.4.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.4.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient') do
    its('EnableMulticast') { should cmp 0 }
  end
end

control 'cis-18.6.5.1' do
  impact 1.0
  title 'Ensure Enable Font Providers is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.5.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('EnableFontProviders') { should cmp 0 }
  end
end

control 'cis-18.6.7.1' do
  impact 1.0
  title "Ensure 'Audit client does not support encryption' is set to Enabled"
  desc 'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.1.'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end

  tag cis_id: '18.6.7.1'

  reg = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer')

  only_if('AuditClientDoesNotSupportEncryption value exists') do
    reg.has_property?('AuditClientDoesNotSupportEncryption')
  end

  describe reg do
    its('AuditClientDoesNotSupportEncryption') { should cmp 1 }
  end
end

control 'cis-18.6.7.2' do
  impact 1.0
  title "Ensure 'Audit client does not support signing' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.7.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer') do
    its('AuditClientDoesNotSupportSigning') { should cmp 1 }
  end
end

control 'cis-18.6.7.3' do
  impact 1.0
  title "Ensure 'Audit insecure guest logon' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.7.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer') do
    its('AuditInsecureGuestLogon') { should cmp 1 }
  end
end

control 'cis-18.6.7.4' do
  impact 1.0
  title "Ensure 'Enable remote mailslots' is set to Disabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.7.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Bowser') do
    its('EnableMailslots') { should cmp 0 }
  end
end

control 'cis-18.6.7.5' do
  impact 1.0
  title "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.7.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer') do
    its('MinSmb2Dialect') { should cmp 785 }
  end
end

control 'cis-18.6.7.6' do
  impact 1.0
  title "Ensure 'Set authentication rate limiter delay (milliseconds)' is set to Enabled: 2000 or more"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.7.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.7.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer') do
    its('InvalidAuthenticationDelayTimeInMs') { should cmp 2000 }
  end
end

control 'cis-18.6.8.1' do
  impact 1.0
  title "Ensure 'Audit insecure guest logon' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AuditInsecureGuestLogon') { should cmp 1 }
  end
end

control 'cis-18.6.8.2' do
  impact 1.0
  title "Ensure 'Audit server does not support encryption' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AuditServerDoesNotSupportEncryption') { should cmp 1 }
  end
end

control 'cis-18.6.8.3' do
  impact 1.0
  title "Ensure 'Audit server does not support signing' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AuditServerDoesNotSupportSigning') { should cmp 1 }
  end
end

control 'cis-18.6.8.4' do
  impact 1.0
  title "Ensure 'Enable authentication rate limiter' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanServer') do
    its('EnableAuthRateLimiter') { should cmp 1 }
  end
end

control 'cis-18.6.8.5' do
  impact 1.0
  title 'Ensure Enable insecure guest logons is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('AllowInsecureGuestAuth') { should cmp 0 }
  end
end

control 'cis-18.6.8.6' do
  impact 1.0
  title "Ensure 'Enable remote mailslots' is set to Disabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider') do
    its('EnableMailslots') { should cmp 0 }
  end
end

control 'cis-18.6.8.7' do
  impact 1.0
  title "Ensure 'Mandate the minimum version of SMB' is set to Enabled: 3.1.1"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('MinSmb2Dialect') { should cmp 785 }
  end
end

control 'cis-18.6.8.8' do
  impact 1.0
  title "Ensure 'Require Encryption' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.8.8.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.8.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
    its('RequireEncryption') { should cmp 1 }
  end
end

control 'cis-18.6.9.1' do
  impact 1.0
  title 'Ensure Turn on Mapper I/O (LLTDIO) driver is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.9.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.9.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD') do
    its('AllowLLTDIOOnDomain') { should cmp 0 }
  end
end

control 'cis-18.6.9.2' do
  impact 1.0
  title 'Ensure Turn on Responder (RSPNDR) driver is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.9.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.9.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD') do
    its('AllowRspndrOnDomain') { should cmp 0 }
  end
end

control 'cis-18.6.10.2' do
  impact 1.0
  title 'Ensure Turn off Microsoft Peer-to-Peer Networking Services is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.10.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.10.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet') do
    its('Disabled') { should cmp 1 }
  end
end

control 'cis-18.6.11.2' do
  impact 1.0
  title 'Ensure Prohibit installation and configuration of Network Bridge on your DNS domain network is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.11.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.11.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    its('NC_AllowNetBridge_NLA') { should cmp 0 }
  end
end

control 'cis-18.6.11.3' do
  impact 1.0
  title 'Ensure Prohibit use of Internet Connection Sharing on your DNS domain network is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.11.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.11.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    its('NC_ShowSharedAccessUI') { should cmp 0 }
  end
end

control 'cis-18.6.11.4' do
  impact 1.0
  title 'Ensure Require domain users to elevate when setting a networks location is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.11.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.11.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    its('NC_StdDomainUserSetLocation') { should cmp 1 }
  end
end

control 'cis-18.6.14.1' do
  impact 1.0
  title "Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication, Require Integrity, and Require Privacy set for all NETLOGON and SYSVOL shares'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.14.1.'

  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end

  tag cis_id: '18.6.14.1'

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    it { should have_property_value('\\\\*\\NETLOGON', :string,
           'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1') }

    it { should have_property_value('\\\\*\\SYSVOL', :string,
           'RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1') }
  end
end


control 'cis-18.6.19.2.1' do
  impact 1.0
  title 'Ensure Disable IPv6: TCPIP6 Parameter DisabledComponents is set to 0xff (255)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.19.2.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.19.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters') do
    its('DisabledComponents') { should cmp 255 }
  end
end

control 'cis-18.6.20.1' do
  impact 1.0
  title 'Ensure Configuration of wireless settings using Windows Connect Now is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.20.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.20.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wcn\Registrars') do
    its('EnableRegistrars') { should cmp 0 }
  end
end

control 'cis-18.6.20.2' do
  impact 1.0
  title 'Ensure Prohibit access of the Windows Connect Now wizards is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.20.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.20.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wcn\Ui') do
    its('DisableWcnUi') { should cmp 1 }
  end
end

control 'cis-18.6.21.1' do
  impact 1.0
  title "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 - Prevent Wi-Fi when on Ethernet'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.21.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.6.21.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wcmsvc\Grouppolicy') do
    its('fMinimizeConnections') { should cmp 3 }
  end
end

control 'cis-18.6.21.2' do
  impact 1.0
  title 'Ensure Prohibit connection to non-domain networks when connected to domain authenticated network is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.6.21.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.6.21.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wcmsvc\Grouppolicy') do
    its('fBlockNonDomain') { should cmp 1 }
  end
end

control 'cis-18.7.1' do
  impact 1.0
  title 'Ensure Allow Print Spooler to accept client connections is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.1.'
  only_if('Level 1 or Level 2 controls enabled') { input('run_level_1') || input('run_level_2') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    its('RegisterSpoolerRemoteRpcEndPoint') { should cmp 2 }
  end
end

control 'cis-18.7.2' do
  impact 1.0
  title "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    its('RedirectionguardPolicy') { should cmp 1 }
  end
end

control 'cis-18.7.3' do
  impact 1.0
  title "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC') do
    its('RpcUseNamedPipeProtocol') { should cmp 0 }
  end
end

control 'cis-18.7.4' do
  impact 1.0
  title 'Ensure Configure RPC connection settings: Use authentication for outgoing RPC connections is set to Enabled: Default'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC') do
    its('RpcAuthentication') { should cmp 0 }
  end
end

control 'cis-18.7.5' do
  impact 1.0
  title "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC') do
    its('RpcProtocols') { should cmp 5 }
  end
end

control 'cis-18.7.6' do
  impact 1.0
  title 'Ensure Configure RPC listener settings: Authentication protocol to use for incoming RPC connections is set to Enabled: Negotiate or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC') do
    its('ForceKerberosForRpc') { should cmp 0 }
  end
end

control 'cis-18.7.7' do
  impact 1.0
  title 'Ensure Configure RPC over TCP port is set to Enabled: 0'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC') do
    its('RpcTcpPort') { should cmp 0 }
  end
end

control 'cis-18.7.8' do
  impact 1.0
  title "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.8.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print') do
    its('RpcAuthnLevelPrivacyEnabled') { should cmp 1 }
  end
end

control 'cis-18.7.9' do
  impact 1.0
  title "Ensure 'Configure Windows protected print' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.9.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.9'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\WPP') do
    its('WindowsProtectedPrintGroupPolicyState') { should cmp 1 }
  end
end

control 'cis-18.7.10' do
  impact 1.0
  title 'Ensure Limits print driver installation to Administrators is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.10.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.10'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('RestrictDriverInstallationToAdministrators') { should cmp 1 }
  end
end

control 'cis-18.7.11' do
  impact 1.0
  title 'Ensure Manage processing of Queue-specific files is set to Enabled: Limit Queue-specific files to Color profiles'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.11.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.11'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    its('CopyFilesPolicy') { should cmp 1 }
  end
end

control 'cis-18.7.12' do
  impact 1.0
  title 'Ensure Point and Print Restrictions: When installing drivers for a new connection is set to Enabled: Show warning and elevation prompt'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.12.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.12'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('NoWarningNoElevationOnInstall') { should cmp 0 }
  end
end

control 'cis-18.7.13' do
  impact 1.0
  title 'Ensure Point and Print Restrictions: When updating drivers for an existing connection is set to Enabled: Show warning and elevation prompt'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.7.13.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.7.13'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint') do
    its('UpdatePromptSettings') { should cmp 0 }
  end
end

control 'cis-18.8.1.1' do
  impact 1.0
  title 'Ensure Turn off notifications network usage is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.8.1.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.8.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications') do
    its('NoCloudApplicationNotification') { should cmp 1 }
  end
end

control 'cis-18.9.3.1' do
  impact 1.0
  title 'Ensure Include command line in process creation events is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.3.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.3.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') do
    its('ProcessCreationIncludeCmdLine_Enabled') { should cmp 1 }
  end
end

control 'cis-18.9.4.1' do
  impact 1.0
  title 'Ensure Encryption Oracle Remediation is set to Enabled: Force Updated Clients'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters') do
    its('AllowEncryptionOracle') { should cmp 0 }
  end
end

control 'cis-18.9.4.2' do
  impact 1.0
  title 'Ensure Remote host allows delegation of non-exportable credentials is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') do
    its('AllowProtectedCreds') { should cmp 1 }
  end
end

control 'cis-18.9.5.1' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.1.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('EnableVirtualizationBasedSecurity') { should cmp 1 }
  end
end

control 'cis-18.9.5.2' do
  impact 1.0
  title "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.2.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('RequirePlatformSecurityFeatures') { should cmp 3 }
  end
end

control 'cis-18.9.5.3' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity is set to Enabled with UEFI lock'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.3.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.5.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('HypervisorEnforcedCodeIntegrity') { should cmp 1 }
  end
end

control 'cis-18.9.5.4' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security: Require UEFI Memory Attributes Table is set to True (checked)'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.4.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.5.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('HVCIMATRequired') { should cmp 1 }
  end
end

control 'cis-18.9.5.5' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security: Credential Guard Configuration is set to Enabled with UEFI lock'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.5.'
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.5.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('LsaCfgFlags') { should cmp 1 }
  end
end

control 'cis-18.9.5.6' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security: Credential Guard Configuration is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.6.'
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '18.9.5.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('LsaCfgFlags') { should cmp 0 }
  end
end

control 'cis-18.9.5.7' do
  impact 1.0
  title 'Ensure Turn On Virtualization Based Security: Secure Launch Configuration is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.5.7.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.5.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
    its('ConfigureSystemGuardLaunch') { should cmp 1 }
  end
end

control 'cis-18.9.7.2' do
  impact 1.0
  title 'Ensure Prevent device metadata retrieval from the Internet is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.7.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.7.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata') do
    its('PreventDeviceMetadataFromNetwork') { should cmp 1 }
  end
end

control 'cis-18.9.13.1' do
  impact 1.0
  title "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.13.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.13.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Earlylaunch') do
    its('DriverLoadPolicy') { should cmp 3 }
  end
end

control 'cis-18.9.19.2' do
  impact 1.0
  title "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378Eac-683F-11D2-A89A-00C04Fbbcfa2}') do
    its('NoBackgroundPolicy') { should cmp 0 }
  end
end

control 'cis-18.9.19.3' do
  impact 1.0
  title 'Ensure Configure registry policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378Eac-683F-11D2-A89A-00C04Fbbcfa2}') do
    its('NoGPOListChanges') { should cmp 0 }
  end
end

control 'cis-18.9.19.4' do
  impact 1.0
  title 'Ensure Configure security policy processing: Do not apply during periodic background processing is set to Enabled: FALSE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}') do
    its('NoBackgroundPolicy') { should cmp 0 }
  end
end

control 'cis-18.9.19.5' do
  impact 1.0
  title 'Ensure Configure security policy processing: Process even if the Group Policy objects have not changed is set to Enabled: TRUE'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}') do
    its('NoGPOListChanges') { should cmp 0 }
  end
end

control 'cis-18.9.19.6' do
  impact 1.0
  title 'Ensure Continue experiences on this device is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('EnableCdp') { should cmp 0 }
  end
end

control 'cis-18.9.19.7' do
  impact 1.0
  title 'Ensure Turn off background refresh of Group Policy is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.19.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.19.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy') do
    its('DisableBkGndGroupPolicy') { should cmp 0 }
  end
end

control 'cis-18.9.20.1.1' do
  impact 1.0
  title 'Ensure Turn off downloading of print drivers over HTTP is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    its('DisableWebPnPDownload') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.2' do
  impact 1.0
  title 'Ensure Turn off handwriting personalization data sharing is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Tabletpc') do
    its('PreventHandwritingDataSharing') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.3' do
  impact 1.0
  title 'Ensure Turn off handwriting recognition error reporting is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.3.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Handwritingerrorreports') do
    its('PreventHandwritingErrorReports') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.4' do
  impact 1.0
  title 'Ensure Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.4.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard') do
    its('ExitOnMSICW') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.5' do
  impact 1.0
  title 'Ensure Turn off Internet download for Web publishing and online ordering wizards is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoWebServices') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.6' do
  impact 1.0
  title 'Ensure Turn off printing over HTTP is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.6.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    its('DisableHTTPPrinting') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.7' do
  impact 1.0
  title 'Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.7.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control') do
    its('NoRegistration') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.8' do
  impact 1.0
  title 'Ensure Turn off Search Companion content file updates is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.8.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Searchcompanion') do
    its('DisableContentFileUpdates') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.9' do
  impact 1.0
  title 'Ensure Turn off the Order Prints picture task is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.9.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.9'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoOnlinePrintsWizard') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.10' do
  impact 1.0
  title 'Ensure Turn off the Publish to Web task for files and folders is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.10.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.10'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoPublishingWizard') { should cmp 1 }
  end
end

control 'cis-18.9.20.1.11' do
  impact 1.0
  title 'Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.11.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.11'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client') do
    its('CEIP') { should cmp 2 }
  end
end

control 'cis-18.9.20.1.12' do
  impact 1.0
  title 'Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.12.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.12'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Sqmclient\Windows') do
    its('CEIPEnable') { should cmp 0 }
  end
end

control 'cis-18.9.20.1.13' do
  impact 1.0
  title 'Ensure Turn off Windows Error Reporting is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.20.1.13.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.20.1.13'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting') do
    its('Disabled') { should cmp 1 }
  end
end

control 'cis-18.9.23.1' do
  impact 1.0
  title 'Ensure Support device authentication using certificate is set to Enabled: Automatic'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.23.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.23.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters') do
    its('DevicePKInitBehavior') { should cmp 0 }
  end
end

control 'cis-18.9.24.1' do
  impact 1.0
  title 'Ensure Enumeration policy for external devices incompatible with Kernel DMA Protection is set to Enabled: Block All'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.24.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.24.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection') do
    its('DeviceEnumerationPolicy') { should cmp 0 }
  end
end

control 'cis-18.9.25.1' do
  impact 1.0
  title 'Ensure Configure password backup directory is set to Enabled: Active Directory or Enabled: Azure Active Directory'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('BackupDirectory') { should cmp 1 }
  end
end

control 'cis-18.9.25.2' do
  impact 1.0
  title 'Ensure Do not allow password expiration time longer than required by policy is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PwdExpirationProtectionEnabled') { should cmp 1 }
  end
end

control 'cis-18.9.25.3' do
  impact 1.0
  title 'Ensure Enable password encryption is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('ADPasswordEncryptionEnabled') { should cmp 1 }
  end
end

control 'cis-18.9.25.4' do
  impact 1.0
  title "Ensure Password Settings: Password Complexity is set to 'Enabled: Large letters + small letters + numbers + special character'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PasswordComplexity') { should cmp 4 }
  end
end

control 'cis-18.9.25.5' do
  impact 1.0
  title 'Ensure Password Settings: Password Length is set to Enabled: 15 or more'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PasswordLength') { should cmp 15 }
  end
end

control 'cis-18.9.25.6' do
  impact 1.0
  title 'Ensure Password Settings: Password Age (Days) is set to Enabled: 30 or fewer'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PasswordAgeDays') { should cmp 30 }
  end
end

control 'cis-18.9.25.7' do
  impact 1.0
  title 'Ensure Post-authentication actions: Grace period (hours) is set to Enabled: 8 or fewer hours, but not 0'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PostAuthenticationResetDelay') { should cmp 8 }
  end
end

control 'cis-18.9.25.8' do
  impact 1.0
  title 'Ensure Post-authentication actions: Actions is set to Enabled: Reset the password and logoff the managed account or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.25.8.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.25.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS') do
    its('PostAuthenticationActions') { should cmp 3 }
  end
end

control 'cis-18.9.26.1' do
  impact 1.0
  title 'Ensure Allow Custom SSPs and APs to be loaded into LSASS is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.26.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.26.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('AllowCustomSSPsAPs') { should cmp 0 }
  end
end

control 'cis-18.9.26.2' do
  impact 1.0
  title 'Ensure Configures LSASS to run as a protected process is set to Enabled: Enabled with UEFI Lock'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.26.2.'
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.26.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    its('RunAsPPL') { should cmp 1 }
  end
end

control 'cis-18.9.27.1' do
  impact 1.0
  title 'Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.27.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.27.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Control Panel\International') do
    its('BlockUserInputMethodsForSignIn') { should cmp 1 }
  end
end

control 'cis-18.9.28.1' do
  impact 1.0
  title 'Ensure Block user from showing account details on sign-in is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('BlockUserFromShowingAccountDetailsOnSignin') { should cmp 1 }
  end
end

control 'cis-18.9.28.2' do
  impact 1.0
  title 'Ensure Do not display network selection UI is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('DontDisplayNetworkSelectionUI') { should cmp 1 }
  end
end

control 'cis-18.9.28.3' do
  impact 1.0
  title 'Ensure Do not enumerate connected users on domain-joined computers is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('DontEnumerateConnectedUsers') { should cmp 1 }
  end
end

control 'cis-18.9.28.4' do
  impact 1.0
  title 'Ensure Enumerate local users on domain-joined computers is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.28.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('EnumerateLocalUsers') { should cmp 0 }
  end
end

control 'cis-18.9.28.5' do
  impact 1.0
  title 'Ensure Turn off app notifications on the lock screen is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('DisableLockScreenAppNotifications') { should cmp 1 }
  end
end

control 'cis-18.9.28.6' do
  impact 1.0
  title 'Ensure Turn off picture password sign-in is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('BlockDomainPicturePassword') { should cmp 1 }
  end
end

control 'cis-18.9.28.7' do
  impact 1.0
  title 'Ensure Turn on convenience PIN sign-in is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.28.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.28.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('AllowDomainPINLogon') { should cmp 0 }
  end
end

control 'cis-18.9.30.1.1' do
  impact 1.0
  title "Ensure 'Block NetBIOS-based discovery for domain controller location' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.30.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.30.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Netlogon\Parameters') do
    its('BlockNetbiosDiscovery') { should cmp 1 }
  end
end

control 'cis-18.9.31.1' do
  impact 1.0
  title 'Ensure Allow Clipboard synchronization across devices is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.31.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.31.1'
  
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System').exist?
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
      its('AllowCrossDeviceClipboard') { should cmp 0 }
    end
  else
    describe 'AllowCrossDeviceClipboard Registry Setting' do
      skip 'Registry key does not exist - policy not configured'
    end
  end
end

control 'cis-18.9.31.2' do
  impact 1.0
  title 'Ensure Allow upload of User Activities is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.31.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.31.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('UploadUserActivities') { should cmp 0 }
  end
end

control 'cis-18.9.33.6.1' do
  impact 1.0
  title 'Ensure Allow network connectivity during connected-standby on battery is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.33.6.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.33.6.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9') do
    its('DCSettingIndex') { should cmp 0 }
  end
end

control 'cis-18.9.33.6.2' do
  impact 1.0
  title 'Ensure Allow network connectivity during connected-standby plugged in is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.33.6.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.33.6.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9') do
    its('ACSettingIndex') { should cmp 0 }
  end
end

control 'cis-18.9.33.6.3' do
  impact 1.0
  title 'Ensure Require a password when a computer wakes on battery is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.33.6.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.33.6.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    its('DCSettingIndex') { should cmp 1 }
  end
end

control 'cis-18.9.33.6.4' do
  impact 1.0
  title 'Ensure Require a password when a computer wakes plugged in is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.33.6.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.33.6.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
    its('ACSettingIndex') { should cmp 1 }
  end
end

control 'cis-18.9.35.1' do
  impact 1.0
  title 'Ensure Configure Offer Remote Assistance is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.35.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.35.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowUnsolicited') { should cmp 0 }
  end
end

control 'cis-18.9.35.2' do
  impact 1.0
  title 'Ensure Configure Solicited Remote Assistance is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.35.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.35.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fAllowToGetHelp') { should cmp 0 }
  end
end

control 'cis-18.9.36.1' do
  impact 1.0
  title 'Ensure Enable RPC Endpoint Mapper Client Authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.36.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.36.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    its('EnableAuthEpResolution') { should cmp 1 }
  end
end

control 'cis-18.9.36.2' do
  impact 1.0
  title 'Ensure Restrict Unauthenticated RPC clients is set to Enabled: Authenticated'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.36.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.36.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    its('RestrictRemoteClients') { should cmp 1 }
  end
end

control 'cis-18.9.39.1' do
  impact 1.0
  title 'Ensure Configure validation of ROCA-vulnerable WHfB keys during authentication is set to Enabled: Audit or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.39.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '18.9.39.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM') do
    its('SamNGCKeyROCAValidation') { should cmp 1 }
  end
end

control 'cis-18.9.39.2' do
  impact 1.0
  title "Ensure 'Configure SAM change password RPC methods policy' is set to Enabled: Allow strong encryption change password RPC method only"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.39.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Domain Controller') do
    input('server_role').to_s.strip.downcase == 'domain_controller'
  end
  tag cis_id: '18.9.39.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM') do
    its('SamrChangeUserPasswordApiPolicy') { should cmp 2 }
  end
end

control 'cis-18.9.39.3' do
  impact 1.0
  title "Ensure 'Configure SAM change password RPC methods policy' is set to Enabled: Block all change password RPC methods"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.39.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.39.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM') do
    its('SamrChangeUserPasswordApiPolicy') { should cmp 1 }
  end
end

control 'cis-18.9.47.5.1' do
  impact 1.0
  title 'Ensure Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.47.5.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.47.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Scripteddiagnosticsprovider\Policy') do
    its('DisableQueryRemoteServer') { should cmp 0 }
  end
end

control 'cis-18.9.47.11.1' do
  impact 1.0
  title 'Ensure Enable/Disable PerfTrack is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.47.11.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.47.11.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Wdi\{9C5A40Da-B965-4Fc3-8781-88Dd50A6299D}') do
    its('ScenarioExecutionEnabled') { should cmp 0 }
  end
end

control 'cis-18.9.49.1' do
  impact 1.0
  title 'Ensure Turn off the advertising ID is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.49.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.49.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Advertisinginfo') do
    its('DisabledByGroupPolicy') { should cmp 1 }
  end
end

control 'cis-18.9.51.1.1' do
  impact 1.0
  title 'Ensure Enable Windows NTP Client is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.51.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.9.51.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\Timeproviders\Ntpclient') do
    its('Enabled') { should cmp 1 }
  end
end

control 'cis-18.9.51.1.2' do
  impact 1.0
  title 'Ensure Enable Windows NTP Server is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.9.51.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server') do
    input('server_role').to_s.strip.downcase == 'member_server'
  end
  tag cis_id: '18.9.51.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\Timeproviders\Ntpserver') do
    its('Enabled') { should cmp 0 }
  end
end

control 'cis-18.10.4.1' do
  impact 1.0
  title 'Ensure Allow a Windows app to share application data between users is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.4.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Appmodel\Statemanager') do
    its('AllowSharedLocalAppData') { should cmp 0 }
  end
end

control 'cis-18.10.4.2' do
  impact 1.0
  title "Ensure 'Not allow per-user unsigned packages to install by default' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Appx') do
    its('DisablePerUserUnsignedPackagesByDefault') { should cmp 1 }
  end
end

control 'cis-18.10.6.1' do
  impact 1.0
  title 'Ensure Allow Microsoft accounts to be optional is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.6.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.6.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('MSAOptional') { should cmp 1 }
  end
end

control 'cis-18.10.8.1' do
  impact 1.0
  title 'Ensure Disallow Autoplay for non-volume devices is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.8.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.8.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    its('NoAutoplayfornonVolume') { should cmp 1 }
  end
end

control 'cis-18.10.8.2' do
  impact 1.0
  title 'Ensure Set the default behavior for AutoRun is set to Enabled: Do not execute any autorun commands'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.8.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.8.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoAutorun') { should cmp 1 }
  end
end

control 'cis-18.10.8.3' do
  impact 1.0
  title 'Ensure Turn off Autoplay is set to Enabled: All drives'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.8.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.8.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('NoDriveTypeAutoRun') { should cmp 255 }
  end
end

control 'cis-18.10.9.1.1' do
  impact 1.0
  title 'Ensure Configure enhanced anti-spoofing is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.9.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.9.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\Facialfeatures') do
    its('EnhancedAntiSpoofing') { should cmp 1 }
  end
end

control 'cis-18.10.11.1' do
  impact 1.0
  title 'Ensure Allow Use of Camera is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.11.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.11.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera') do
    its('AllowCamera') { should cmp 0 }
  end
end

control 'cis-18.10.13.1' do
  impact 1.0
  title 'Ensure Turn off cloud consumer account state content is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.13.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.13.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent') do
    its('DisableConsumerAccountStateContent') { should cmp 1 }
  end
end

control 'cis-18.10.13.2' do
  impact 1.0
  title 'Ensure Turn off cloud optimized content is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.13.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.13.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent') do
    its('DisableCloudOptimizedContent') { should cmp 1 }
  end
end

control 'cis-18.10.13.3' do
  impact 1.0
  title 'Ensure Turn off Microsoft consumer experiences is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.13.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.13.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Cloudcontent') do
    its('DisableWindowsConsumerFeatures') { should cmp 1 }
  end
end

control 'cis-18.10.14.1' do
  impact 1.0
  title 'Ensure Require pin for pairing is set to Enabled: First Time OR Enabled: Always'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.14.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.14.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect') do
    its('RequirePinForPairing') { should cmp 1 }
  end
end

control 'cis-18.10.15.1' do
  impact 1.0
  title 'Ensure Do not display the password reveal button is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.15.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.15.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Credui') do
    its('DisablePasswordReveal') { should cmp 1 }
  end
end

control 'cis-18.10.15.2' do
  impact 1.0
  title 'Ensure Enumerate administrator accounts on elevation is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.15.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.15.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
    its('EnumerateAdministrators') { should cmp 0 }
  end
end

control 'cis-18.10.16.1' do
  impact 1.0
  title 'Ensure Allow Diagnostic Data is set to Enabled: Diagnostic data off (not recommended) or Enabled: Send required diagnostic data'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('AllowTelemetry') { should cmp 1 }
  end
end

control 'cis-18.10.16.2' do
  impact 1.0
  title 'Ensure Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('DisableEnterpriseAuthProxy') { should cmp 1 }
  end
end

control 'cis-18.10.16.3' do
  impact 1.0
  title 'Ensure Disable OneSettings Downloads is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('DisableOneSettingsDownloads') { should cmp 1 }
  end
end

control 'cis-18.10.16.4' do
  impact 1.0
  title 'Ensure Do not show feedback notifications is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Datacollection') do
    its('DoNotShowFeedbackNotifications') { should cmp 1 }
  end
end

control 'cis-18.10.16.5' do
  impact 1.0
  title 'Ensure Enable OneSettings Auditing is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('EnableOneSettingsAuditing') { should cmp 1 }
  end
end

control 'cis-18.10.16.6' do
  impact 1.0
  title 'Ensure Limit Diagnostic Log Collection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDiagnosticLogCollection') { should cmp 1 }
  end
end

control 'cis-18.10.16.7' do
  impact 1.0
  title 'Ensure Limit Dump Collection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.7.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection') do
    its('LimitDumpCollection') { should cmp 1 }
  end
end

control 'cis-18.10.16.8' do
  impact 1.0
  title "Ensure 'Toggle user control over Insider builds' is set to Disabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.16.8.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.16.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds') do
    its('AllowBuildPreview') { should cmp 0 }
  end
end

control 'cis-18.10.18.1' do
  impact 1.0
  title 'Ensure Enable App Installer is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableAppInstaller') { should cmp 0 }
  end
end

control 'cis-18.10.18.2' do
  impact 1.0
  title 'Ensure Enable App Installer Experimental Features is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableExperimentalFeatures') { should cmp 0 }
  end
end

control 'cis-18.10.18.3' do
  impact 1.0
  title 'Ensure Enable App Installer Hash Override is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableHashOverride') { should cmp 0 }
  end
end

control 'cis-18.10.18.4' do
  impact 1.0
  title 'Ensure Enable App Installer Local Archive Malware Scan Override is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableLocalArchiveMalwareScanOverride') { should cmp 0 }
  end
end

control 'cis-18.10.18.5' do
  impact 1.0
  title 'Ensure Enable App Installer ms-appinstaller protocol is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableMSAppInstallerProtocol') { should cmp 0 }
  end
end

control 'cis-18.10.18.6' do
  impact 1.0
  title 'Ensure Enable App Installer Microsoft Store Source Certificate Validation Bypass is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.6.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableBypassCertificatePinningForMicrosoftStore') { should cmp 0 }
  end
end

control 'cis-18.10.18.7' do
  impact 1.0
  title 'Ensure Enable Windows Package Manager command line interfaces is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.18.7.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.18.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppInstaller') do
    its('EnableWindowsPackageManagerCommandLineInterfaces') { should cmp 0 }
  end
end

control 'cis-18.10.26.1.1' do
  impact 1.0
  title 'Ensure Application Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application') do
    its('Retention') { should cmp 0 }
  end
end

control 'cis-18.10.26.1.2' do
  impact 1.0
  title 'Ensure Application: Specify the maximum log file size (KB) is set to Enabled: 32768 or greater'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Application') do
    its('MaxSize') { should cmp 32768 }
  end
end

control 'cis-18.10.26.2.1' do
  impact 1.0
  title 'Ensure Security Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Security') do
    its('Retention') { should cmp 0 }
  end
end

control 'cis-18.10.26.2.2' do
  impact 1.0
  title 'Ensure Security: Specify the maximum log file size (KB) is set to Enabled: 196608 or greater'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.2.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Security') do
    its('MaxSize') { should cmp 196608 }
  end
end

control 'cis-18.10.26.3.1' do
  impact 1.0
  title 'Ensure Setup Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.3.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.3.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Setup') do
    its('Retention') { should cmp 0 }
  end
end

control 'cis-18.10.26.3.2' do
  impact 1.0
  title 'Ensure Setup: Specify the maximum log file size (KB) is set to Enabled: 32768 or greater'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.3.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.3.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\Setup') do
    its('MaxSize') { should cmp 32768 }
  end
end

control 'cis-18.10.26.4.1' do
  impact 1.0
  title 'Ensure System Control Event Log behavior when the log file reaches its maximum size is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\System') do
    its('Retention') { should cmp 0 }
  end
end

control 'cis-18.10.26.4.2' do
  impact 1.0
  title 'Ensure System: Specify the maximum log file size (KB) is set to Enabled: 32768 or greater'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.26.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.26.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Eventlog\System') do
    its('MaxSize') { should cmp 32768 }
  end
end

control 'cis-18.10.29.2' do
  impact 1.0
  title 'Ensure Do not apply the Mark of the Web tag to files copied from insecure sources is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.29.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.29.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    its('DisableMotWOnInsecurePathCopy') { should cmp 0 }
  end
end

control 'cis-18.10.29.3' do
  impact 1.0
  title 'Ensure Turn off Data Execution Prevention for Explorer is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.29.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.29.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    its('NoDataExecutionPrevention') { should cmp 0 }
  end
end

control 'cis-18.10.29.4' do
  impact 1.0
  title 'Ensure Turn off heap termination on corruption is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.29.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.29.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    its('NoHeapTerminationOnCorruption') { should cmp 0 }
  end
end

control 'cis-18.10.29.5' do
  impact 1.0
  title 'Ensure Turn off shell protocol protected mode is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.29.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.29.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    its('PreXPSP2ShellProtocolBehavior') { should cmp 0 }
  end
end

control 'cis-18.10.37.1' do
  impact 1.0
  title 'Ensure Turn off location is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.37.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.37.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Locationandsensors') do
    its('DisableLocation') { should cmp 1 }
  end
end

control 'cis-18.10.41.1' do
  impact 1.0
  title 'Ensure Allow Message Service Cloud Sync is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.41.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.41.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging') do
    its('AllowMessageSync') { should cmp 0 }
  end
end

control 'cis-18.10.42.1' do
  impact 1.0
  title 'Ensure Block all consumer Microsoft account user authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.42.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.42.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount') do
    its('DisableUserAuth') { should cmp 1 }
  end
end

control 'cis-18.10.43.4.1' do
  impact 1.0
  title 'Ensure Enable EDR in block mode is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Features') do
    its('PassiveRemediation') { should cmp 1 }
  end
end

control 'cis-18.10.43.5.1' do
  impact 1.0
  title 'Ensure Configure local setting override for reporting to Microsoft MAPS is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.5.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.5.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet') do
    its('LocalSettingOverrideSpynetReporting') { should cmp 0 }
  end
end

control 'cis-18.10.43.5.2' do
  impact 1.0
  title 'Ensure Join Microsoft MAPS is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.5.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.5.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet') do
    its('SpynetReporting') { should cmp 0 }
  end
end

control 'cis-18.10.43.6.1.1' do
  impact 1.0
  title 'Ensure Configure Attack Surface Reduction rules is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.6.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.6.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR') do
    its('ExploitGuard_ASR_Rules') { should cmp 1 }
  end
end

control 'cis-18.10.43.6.1.2' do
  impact 1.0
  title 'Ensure Configure Attack Surface Reduction rules: Set the state for each ASR rule is configured'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.6.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  tag cis_id: '18.10.43.6.1.2'
  
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules') do
    it { should exist }
  end
end

control 'cis-18.10.43.6.3.1' do
  impact 1.0
  title 'Ensure Prevent users and apps from accessing dangerous websites is set to Enabled: Block'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.6.3.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.6.3.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection') do
    its('EnableNetworkProtection') { should cmp 1 }
  end
end

control 'cis-18.10.43.7.1' do
  impact 1.0
  title 'Ensure Enable file hash computation feature is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.7.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.7.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine') do
    its('EnableFileHashComputation') { should cmp 1 }
  end
end

control 'cis-18.10.43.8.1' do
  impact 1.0
  title 'Ensure Convert warn verdict to block is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.8.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.8.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS') do
    its('EnableConvertWarnToBlock') { should cmp 1 }
  end
end

control 'cis-18.10.43.10.1' do
  impact 1.0
  title 'Ensure Configure real-time protection and Security Intelligence Updates during OOBE is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.10.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.10.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') do
    its('OobeEnableRtpAndSigUpdate') { should cmp 1 }
  end
end

control 'cis-18.10.43.10.2' do
  impact 1.0
  title 'Ensure Scan all downloaded files and attachments is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.10.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.10.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') do
    its('DisableIOAVProtection') { should cmp 0 }
  end
end

control 'cis-18.10.43.10.3' do
  impact 1.0
  title "Ensure 'Turn off real-time protection' is set to 'Disabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.10.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.10.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') do
    its('DisableRealtimeMonitoring') { should cmp 0 }
  end
end

control 'cis-18.10.43.10.4' do
  impact 1.0
  title 'Ensure Turn on behavior monitoring is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.10.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.10.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') do
    its('DisableBehaviorMonitoring') { should cmp 0 }
  end
end

control 'cis-18.10.43.10.5' do
  impact 1.0
  title "Ensure 'Turn on script scanning' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.10.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.10.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection') do
    its('DisableScriptScanning') { should cmp 0 }
  end
end

control 'cis-18.10.43.11.1.1.1' do
  impact 1.0
  title 'Ensure Configure Brute-Force Protection aggressiveness is set to Enabled: Medium or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.11.1.1.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.11.1.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection') do
    its('BruteForceProtectionAggressiveness') { should cmp 1 }
  end
end

control 'cis-18.10.43.11.1.1.2' do
  impact 1.0
  title 'Ensure Configure Remote Encryption Protection Mode is set to Enabled: Audit or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.11.1.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.11.1.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection') do
    its('BruteForceProtectionConfiguredState') { should cmp 1 }
  end
end

control 'cis-18.10.43.11.1.2.1' do
  impact 1.0
  title 'Ensure Configure how aggressively Remote Encryption Protection blocks threats is set to Enabled: Medium or higher'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.11.1.2.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.11.1.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection') do
    its('RemoteEncryptionProtectionAggressiveness') { should cmp 1 }
  end
end

control 'cis-18.10.43.12.1' do
  impact 1.0
  title 'Ensure Configure Watson events is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.12.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.12.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting') do
    its('DisableGenericRePorts') { should cmp 1 }
  end
end

control 'cis-18.10.43.13.1' do
  impact 1.0
  title 'Ensure Scan excluded files and directories during quick scans is set to Enabled: 1'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.13.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.13.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan') do
    its('QuickScanIncludeExclusions') { should cmp 1 }
  end
end

control 'cis-18.10.43.13.2' do
  impact 1.0
  title "Ensure 'Scan packed executables' is set to Enabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.13.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.13.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan') do
    its('DisablePackedExeScanning') { should cmp 0 }
  end
end

control 'cis-18.10.43.13.3' do
  impact 1.0
  title 'Ensure Scan removable drives is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.13.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.13.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan') do
    its('DisableRemovableDriveScanning') { should cmp 0 }
  end
end

control 'cis-18.10.43.13.4' do
  impact 1.0
  title "Ensure 'Trigger a quick scan after X days without any scans' is set to Enabled: 7"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.13.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.13.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan') do
    its('DaysUntilAggressiveCatchupQuickScan') { should cmp 7 }
  end
end

control 'cis-18.10.43.13.5' do
  impact 1.0
  title 'Ensure Turn on e-mail scanning is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.13.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.13.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan') do
    its('DisableEmailScanning') { should cmp 0 }
  end
end

control 'cis-18.10.43.16' do
  impact 1.0
  title 'Ensure Configure detection for potentially unwanted applications is set to Enabled: Block'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.16.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.16'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender') do
    its('PUAProtection') { should cmp 1 }
  end
end

control 'cis-18.10.43.17' do
  impact 1.0
  title "Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.43.17.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.43.17'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender') do
    its('HideExclusionsFromLocalUsers') { should cmp 1 }
  end
end

control 'cis-18.10.51.1' do
  impact 1.0
  title 'Ensure Prevent the usage of OneDrive for file storage is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.51.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.51.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive') do
    its('DisableFileSyncNGSC') { should cmp 1 }
  end
end

control 'cis-18.10.56.1' do
  impact 1.0
  title "Ensure 'Turn off Push To Install service' is set to 'Enabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.56.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.56.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall') do
    its('DisablePushToInstall') { should cmp 1 }
  end
end

control 'cis-18.10.57.2.2' do
  impact 1.0
  title 'Ensure Do not allow passwords to be saved is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.2.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DisablePasswordSaving') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.2.1' do
  impact 1.0
  title 'Ensure Restrict Remote Desktop Services users to a single Remote Desktop Services session is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.2.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fSingleSessionPerUser') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.1' do
  impact 1.0
  title 'Ensure Allow UI Automation redirection is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('EnableUiaRedirection') { should cmp 0 }
  end
end

control 'cis-18.10.57.3.3.2' do
  impact 1.0
  title 'Ensure Do not allow COM port redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableCcm') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.3' do
  impact 1.0
  title 'Ensure Do not allow drive redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableCdm') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.4' do
  impact 1.0
  title 'Ensure Do not allow location redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.4.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableLocationRedir') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.5' do
  impact 1.0
  title 'Ensure Do not allow LPT port redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.5.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableLPT') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.6' do
  impact 1.0
  title 'Ensure Do not allow supported Plug and Play device redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.6.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.6'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisablePNPRedir') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.7' do
  impact 1.0
  title 'Ensure Do not allow WebAuthn redirection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.7.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.7'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fDisableWebAuthn') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.3.8' do
  impact 1.0
  title "Ensure 'Restrict clipboard transfer from server to client' is set to 'Enabled: Disable clipboard transfers from server to client'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.3.8.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.3.8'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('SCClipLevel') { should cmp 0 }
  end
end

control 'cis-18.10.57.3.9.1' do
  impact 1.0
  title 'Ensure Always prompt for password upon connection is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.9.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.9.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fPromptForPassword') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.9.2' do
  impact 1.0
  title 'Ensure Require secure RPC communication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.9.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.9.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('fEncryptRPCTraffic') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.9.3' do
  impact 1.0
  title 'Ensure Require use of specific security layer for remote RDP connections is set to Enabled: SSL'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.9.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.9.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('SecurityLayer') { should cmp 2 }
  end
end

control 'cis-18.10.57.3.9.4' do
  impact 1.0
  title 'Ensure Require user authentication for remote connections by using Network Level Authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.9.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.9.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('UserAuthentication') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.9.5' do
  impact 1.0
  title 'Ensure Set client connection encryption level is set to Enabled: High Level'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.9.5.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.9.5'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MinEncryptionLevel') { should cmp 3 }
  end
end

control 'cis-18.10.57.3.10.1' do
  impact 1.0
  title "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less, but not Never (0)'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.10.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.10.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MaxIdleTime') { should cmp 900000 }
  end
end

control 'cis-18.10.57.3.10.2' do
  impact 1.0
  title 'Ensure Set time limit for disconnected sessions is set to Enabled: 1 minute'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.10.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.10.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('MaxDisconnectionTime') { should cmp 60000 }
  end
end

control 'cis-18.10.57.3.11.1' do
  impact 1.0
  title 'Ensure Do not delete temp folders upon exit is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.11.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.11.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('DeleteTempDirsOnExit') { should cmp 1 }
  end
end

control 'cis-18.10.57.3.11.2' do
  impact 1.0
  title 'Ensure Do not use temporary folders per session is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.57.3.11.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.57.3.11.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    its('PerSessionTempDir') { should cmp 1 }
  end
end

control 'cis-18.10.58.1' do
  impact 1.0
  title 'Ensure Prevent downloading of enclosures is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.58.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.58.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds') do
    its('DisableEnclosureDownload') { should cmp 1 }
  end
end

control 'cis-18.10.58.2' do
  impact 1.0
  title "Ensure 'Turn on Basic feed authentication over HTTP' is set to 'Disabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.58.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.58.2'
  describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds') do
    its('AllowBasicAuthInClear') { should cmp 0 }
  end
end

control 'cis-18.10.59.2' do
  impact 1.0
  title 'Ensure Allow Cloud Search is set to Enabled: Disable Cloud Search'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.59.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.59.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    its('AllowCloudSearch') { should cmp 0 }
  end
end

control 'cis-18.10.59.3' do
  impact 1.0
  title 'Ensure Allow indexing of encrypted files is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.59.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.59.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    its('AllowIndexingEncryptedStoresOrItems') { should cmp 0 }
  end
end

control 'cis-18.10.59.4' do
  impact 1.0
  title 'Ensure Allow search highlights is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.59.4.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.59.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    its('EnableDynamicContentInWSB') { should cmp 0 }
  end
end

control 'cis-18.10.63.1' do
  impact 1.0
  title 'Ensure Turn off KMS Client Online AVS Validation is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.63.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.63.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform') do
    its('NoGenTicket') { should cmp 1 }
  end
end

control 'cis-18.10.76.2.1' do
  impact 1.0
  title 'Ensure Configure Windows Defender SmartScreen is set to Enabled: Warn and prevent bypass'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.76.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.76.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    its('EnableSmartScreen') { should cmp 1 }
  end
end

control 'cis-18.10.80.1' do
  impact 1.0
  title 'Ensure Allow suggested apps in Windows Ink Workspace is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.80.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.80.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace') do
    its('AllowSuggestedAppsInWindowsInkWorkspace') { should cmp 0 }
  end
end

control 'cis-18.10.80.2' do
  impact 1.0
  title 'Ensure Allow Windows Ink Workspace is set to Enabled: On, but disallow access above lock OR Enabled: Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.80.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.80.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace') do
    its('AllowWindowsInkWorkspace') { should cmp 1 }
  end
end

control 'cis-18.10.81.1' do
  impact 1.0
  title 'Ensure Allow user control over installs is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.81.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.81.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    its('EnableUserControl') { should cmp 0 }
  end
end

control 'cis-18.10.81.2' do
  impact 1.0
  title "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.81.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.81.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end

control 'cis-18.10.81.3' do
  impact 1.0
  title 'Ensure Prevent Internet Explorer security prompt for Windows Installer scripts is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.81.3.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.81.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    its('SafeForScripting') { should cmp 0 }
  end
end

control 'cis-18.10.82.1' do
  impact 1.0
  title "Ensure Configure the transmission of the user's password in the content of MPR notifications sent by winlogon is set to Disabled"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.82.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.82.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('EnableMPR') { should cmp 0 }
  end
end

control 'cis-18.10.82.2' do
  impact 1.0
  title 'Ensure Sign-in last interactive user automatically after a system-initiated restart is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.82.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.82.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('DisableAutomaticRestartSignOn') { should cmp 1 }
  end
end

control 'cis-18.10.87.1' do
  impact 1.0
  title 'Ensure Turn on PowerShell Script Block Logging is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.87.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.87.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') do
    its('EnableScriptBlockLogging') { should cmp 1 }
  end
end

control 'cis-18.10.87.2' do
  impact 1.0
  title 'Ensure Turn on PowerShell Transcription is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.87.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.87.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Powershell\Transcription') do
    its('EnableTranscripting') { should cmp 1 }
  end
end

control 'cis-18.10.89.1.1' do
  impact 1.0
  title 'Ensure Allow Basic authentication is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Client') do
    its('AllowBasic') { should cmp 0 }
  end
end

control 'cis-18.10.89.1.2' do
  impact 1.0
  title 'Ensure Allow unencrypted traffic is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.1.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.1.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Client') do
    its('AllowUnencryptedTraffic') { should cmp 0 }
  end
end

control 'cis-18.10.89.1.3' do
  impact 1.0
  title 'Ensure Disallow Digest authentication is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.1.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.1.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Client') do
    its('AllowDigest') { should cmp 0 }
  end
end

control 'cis-18.10.89.2.1' do
  impact 1.0
  title 'Ensure Allow Basic authentication is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Service') do
    its('AllowBasic') { should cmp 0 }
  end
end

control 'cis-18.10.89.2.2' do
  impact 1.0
  title 'Ensure Allow remote server management through WinRM is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.2.2.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Service') do
    its('AllowAutoConfig') { should cmp 0 }
  end
end

control 'cis-18.10.89.2.3' do
  impact 1.0
  title 'Ensure Allow unencrypted traffic is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.2.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.2.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Service') do
    its('AllowUnencryptedTraffic') { should cmp 0 }
  end
end

control 'cis-18.10.89.2.4' do
  impact 1.0
  title 'Ensure Disallow WinRM from storing RunAs credentials is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.89.2.4.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.89.2.4'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Service') do
    its('DisableRunAs') { should cmp 1 }
  end
end

control 'cis-18.10.90.1' do
  impact 1.0
  title 'Ensure Allow Remote Shell Access is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.90.1.'
  only_if('Level 2 controls enabled') { input('run_level_2') }
  only_if("Skipped testing Level 2 - only Level 1 enabled") do
    input('run_level_2') || !input('run_level_1')
  end
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.90.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Winrm\Service\Winrs') do
    its('AllowRemoteShellAccess') { should cmp 0 }
  end
end

control 'cis-18.10.92.2.1' do
  impact 1.0
  title 'Ensure Prevent users from modifying settings is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.92.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.92.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection') do
    its('DisallowExploitProtectionOverride') { should cmp 1 }
  end
end

control 'cis-18.10.93.1.1' do
  impact 1.0
  title 'Ensure No auto-restart with logged on users for scheduled automatic updates installations is set to Disabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.1.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.1.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windowsupdate\Au') do
    its('NoAutoRebootWithLoggedOnUsers') { should cmp 0 }
  end
end

control 'cis-18.10.93.2.1' do
  impact 1.0
  title 'Ensure Configure Automatic Updates is set to Enabled'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.2.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.2.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windowsupdate\Au') do
    its('NoAutoUpdate') { should cmp 0 }
  end
end

control 'cis-18.10.93.2.2' do
  impact 1.0
  title 'Ensure Configure Automatic Updates: Scheduled install day is set to 0 - Every day'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.2.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.2.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windowsupdate\Au') do
    its('ScheduledInstallDay') { should cmp 0 }
  end
end

control 'cis-18.10.93.4.1' do
  impact 1.0
  title "Ensure 'Manage preview builds' is set to 'Disabled'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.4.1.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.4.1'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') do
    its('ManagePreviewBuilds') { should cmp 1 }
  end
end

control 'cis-18.10.93.4.2' do
  impact 1.0
  title "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days'"
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.4.2.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.4.2'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferFeatureUpdates') { should cmp 1 }
  end
end

control 'cis-18.10.93.4.3' do
  impact 1.0
  title 'Ensure Select when Quality Updates are received is set to Enabled: 0 days'
  desc  'CIS Microsoft Windows Server 2022 v1.0.0 control 18.10.93.4.3.'
  only_if('Level 1 controls enabled') { input('run_level_1') }
  only_if('Applicable to Member Server or Domain Controller') do
    %w[domain_controller member_server].include?(input('server_role').to_s.strip.downcase)
  end
  tag cis_id: '18.10.93.4.3'
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate') do
    its('DeferQualityUpdates') { should cmp 1 }
  end
end
