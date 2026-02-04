# frozen_string_literal: true

class SeceditPolicy
  EXPORT_CFG = 'C:\Windows\Temp\inspec-secpol.cfg'.freeze

  def initialize(inspec)
    @inspec = inspec
    @cache  = nil
  end

  def export_and_parse
    return @cache if @cache

    cleanup_stale_export
    run_secedit_export

    if export_successful?
      @cache = parse_ini(read_export_file)
      merge_fallback_sources              # System Access: net accounts + LSA + secedit safety net
      merge_security_options_from_registry # NEW: always overlay Security Options from registry
      return @cache
    end

    # Pure registry/net accounts fallback
    @cache = {
      'System Access'    => registry_system_access,
      'Privilege Rights' => {},
      'Security Options' => registry_security_options,
    }
    @cache
  end

  private

  def cleanup_stale_export
    @inspec.command(%(cmd.exe /c del /f /q "#{EXPORT_CFG}" 2>nul))
  end

  def run_secedit_export
    @inspec.command(%(cmd.exe /c secedit /export /cfg "#{EXPORT_CFG}" /areas SECURITYPOLICY USER_RIGHTS /quiet))
  end

  def export_successful?
    f = @inspec.file(EXPORT_CFG)
    f.exist? && f.size > 0
  end

  def read_export_file
    @inspec.file(EXPORT_CFG).content.to_s
  end

  def parse_ini(text)
    out     = Hash.new { |h, k| h[k] = {} }
    current = nil

    text = text.dup
    text.encode!('UTF-8', invalid: :replace, undef: :replace, replace: '')

    text.each_line do |line|
      line = line.chomp.strip
      next if line.empty? || line.start_with?(';')

      if line.start_with?('[') && line.end_with?(']')
        current = line[1..-2].strip
        next
      end

      next unless current

      if (idx = line.index('='))
        key = line[0...idx].strip
        val = line[(idx + 1)..-1].strip
        out[current][key] = val
      end
    end

    out
  end

  # One-off helper to read a single System Access key from secedit,
  # even when the main export branch is not used.
  def secedit_system_access_value(key)
    run_secedit_export
    return nil unless export_successful?

    text = read_export_file
    line = text.each_line.find { |l| l.strip.start_with?("#{key} =") }
    return nil unless line

    raw = line.split('=', 2)[1].to_s.strip
    raw.empty? ? nil : raw
  end

  # Merge net accounts + LSA registry into parsed secedit (when export works)
  def merge_fallback_sources
    return unless @cache['System Access'].is_a?(Hash)

    # net accounts: history / age / lockout
    net = net_accounts_system_access
    net.each { |k, v| @cache['System Access'][k] ||= v }

    # LSA registry for the three account-policy booleans
    lsa = %w[PasswordComplexity ClearTextPassword AllowAdministratorLockout]
          .each_with_object({}) do |k, h|
      h[k] = registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', k)
    end

    lsa.each { |k, v| @cache['System Access'][k] ||= v if v }
  end

  # NEW: Always ensure we have a 'Security Options' section populated from registry,
  # even when secedit export succeeds.
  def merge_security_options_from_registry
    return unless @cache.is_a?(Hash)

    @cache['Security Options'] ||= {}
    reg_opts = registry_security_options
    return unless reg_opts.is_a?(Hash)

    reg_opts.each do |k, v|
      next if v.nil?
      @cache['Security Options'][k] ||= v
    end
  end

  def net_accounts_system_access
    out = {}

    cmd = @inspec.command('cmd.exe /c net accounts')
    return out unless cmd && cmd.exit_status == 0

    cmd.stdout.to_s.each_line do |line|
      line = line.strip
      next if line.empty?

      if line =~ /^Length of password history maintained:\s+(\d+)$/i
        out['PasswordHistorySize'] = Regexp.last_match(1)
      elsif line =~ /^Maximum password age\s*\(days\):\s+(.+)$/i
        out['MaximumPasswordAge'] = normalize_number(Regexp.last_match(1))
      elsif line =~ /^Minimum password age\s*\(days\):\s+(.+)$/i
        out['MinimumPasswordAge'] = normalize_number(Regexp.last_match(1))
      elsif line =~ /^Minimum password length:\s+(\d+)$/i
        out['MinimumPasswordLength'] = Regexp.last_match(1)
      elsif line =~ /^Lockout threshold:\s+(.+)$/i
        out['LockoutBadCount'] = normalize_number(Regexp.last_match(1))
      elsif line =~ /^Lockout duration\s*\(minutes\):\s+(.+)$/i
        out['LockoutDuration'] = normalize_number(Regexp.last_match(1))
      elsif line =~ /^Lockout observation window\s*\(minutes\):\s+(.+)$/i
        out['ResetLockoutCount'] = normalize_number(Regexp.last_match(1))
      end
    end

    out
  end

  def normalize_number(s)
    s = s.to_s.strip
    return '0' if s =~ /^never$/i

    m = s.match(/(-?\d+)/)
    m ? m[1] : nil
  end

  def registry_system_access
    sys = net_accounts_system_access

    lsa = %w[PasswordComplexity AllowAdministratorLockout ClearTextPassword]
          .each_with_object({}) do |k, h|
      h[k] = registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', k)
    end

    merged = sys.merge(lsa) { |_k, a, b| a.nil? ? b : a }

    # Final safety net: if complexity/clear-text/admin-lockout still nil,
    # pull them directly from secedit.
    %w[PasswordComplexity ClearTextPassword AllowAdministratorLockout].each do |k|
      if merged[k].nil?
        val = secedit_system_access_value(k)
        merged[k] = val unless val.nil?
      end
    end

    merged
  end

  def registry_security_options
    {
      'EnableAdminAccount' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'EnableAdminAccount'),
      'EnableGuestAccount' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'EnableGuestAccount'),
      'LimitBlankPasswordUse' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'LimitBlankPasswordUse'),
      'SCENoApplyLegacyAuditPolicy' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy'),
      'AddPrinterDrivers' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers', 'AddPrinterDrivers'),
      'RequireSignOrSeal' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RequireSignOrSeal'),
      'SealSecureChannel' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SealSecureChannel'),
      'SignSecureChannel' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'SignSecureChannel'),
      'RequireStrongKey' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'RequireStrongKey'),
      'DisableCAD' =>
        registry_read('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'DisableCAD'),
      'InactivityTimeoutSecs' =>
        registry_read('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'InactivityTimeoutSecs'),
      'RequireSecuritySignature' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature'),
      'EnableSecuritySignature' =>
        registry_read('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'EnableSecuritySignature'),
    }
  end

  def registry_read(path, key)
    ps = <<~POWERSHELL
      $p = Get-ItemProperty -Path '#{path}' -ErrorAction SilentlyContinue
      if ($p -and ($p.PSObject.Properties.Name -contains '#{key}')) {
        $p.#{key}
      }
    POWERSHELL

    cmd = @inspec.command("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command #{ps.inspect}")
    return nil unless cmd.exit_status == 0

    raw = cmd.stdout.to_s.strip
    return nil if raw.empty?

    if raw.include?(',')
      raw = raw.split(',')[-1].strip
    end

    raw.match?(/^[-]?\d+$/) ? raw.to_i : raw
  end
end

class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export or registry/net accounts fallback.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
  end

  def method_missing(name, *args)
    key = name.to_s
    present, value = lookup_key_present(key)
    return to_typed(value) if present

    super
  end

  def respond_to_missing?(name, include_private = false)
    present, _value = lookup_key_present(name.to_s)
    present || super
  end

  def [](key)
    _present, value = lookup_key_present(key.to_s)
    to_typed(value)
  end

  private

  def lookup_key_present(key)
    return [false, nil] unless @policy.is_a?(Hash)

    @policy.each_value do |section|
      next unless section.is_a?(Hash)
      return [true, section[key]] if section.key?(key)
    end

    [false, nil]
  end

  def to_typed(v)
    return nil if v.nil?

    s = v.to_s.strip
    s.match?(/^[-]?\d+$/) ? s.to_i : s
  end
end

Object.const_set(:SeceditPolicy, SeceditPolicy) unless Object.const_defined?(:SeceditPolicy)
Object.const_set(:LocalSecurityPolicy, LocalSecurityPolicy) unless Object.const_defined?(:LocalSecurityPolicy)
