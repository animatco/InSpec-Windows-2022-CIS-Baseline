# frozen_string_literal: true

# Local Security Policy export parser
# - Uses secedit for SECURITYPOLICY + USER_RIGHTS
# - Falls back to registry for System Access + Security Options
# - Windows Server 2012R2 → 2025 compatible
# - WinRM-safe (no profile temp dirs)
# - FIXED: Robust INI parsing with section/key stripping + LSA overrides
# - Local Security Policy export parser - DEBUG VERSION

class SeceditPolicy
  EXPORT_CFG = 'C:\\Windows\\Temp\\inspec-secpol.cfg'.freeze

  def initialize(inspec)
    @inspec = inspec
    @cache = nil
  end

  def export_and_parse
    return @cache if @cache

    cleanup_stale_export
    run_secedit_export

    if export_successful?
      @cache = parse_ini(read_export_file)
      
      # DEBUG: Show what was actually parsed
      @inspec.command("echo 'DEBUG: Cache keys: #{@cache.keys.inspect}'")
      if @cache['System Access']
        @inspec.command("echo 'DEBUG System Access keys: #{@cache['System Access'].keys.inspect}'")
        @inspec.command("echo 'DEBUG PasswordComplexity: #{@cache['System Access']['PasswordComplexity'].inspect}'")
        @inspec.command("echo 'DEBUG ClearTextPassword: #{@cache['System Access']['ClearTextPassword'].inspect}'")
        @inspec.command("echo 'DEBUG AllowAdministratorLockout: #{@cache['System Access']['AllowAdministratorLockout'].inspect}'")
      end
      
      return @cache
    end

    # Registry fallback
    @cache = build_registry_fallback
    @inspec.command("echo 'DEBUG: Using REGISTRY FALLBACK'")
    @cache
  end

  private

  def build_registry_fallback
    {
      'System Access' => registry_system_access,
      'Privilege Rights' => {},
      'Security Options' => registry_security_options
    }
  end

  # FIXED parse_ini with aggressive stripping
  def parse_ini(text)
    out = Hash.new { |h, k| h[k] = {} }
    current = nil

    text.encode!('UTF-8', invalid: :replace, undef: :replace, replace: '')

    text.each_line do |line|
      line.chomp!  # Remove line endings first
      line.strip!
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

  private

  # Remove stale export file
  def cleanup_stale_export
    @inspec.command(%(cmd.exe /c del /f /q "#{EXPORT_CFG}" 2>nul))
  end

  # Execute secedit export
  def run_secedit_export
    @inspec.command(%(cmd.exe /c secedit /export /cfg "#{EXPORT_CFG}" /areas SECURITYPOLICY USER_RIGHTS /quiet))
  end

  # Check if export succeeded
  def export_successful?
    @inspec.file(EXPORT_CFG).exist? &&
      @inspec.file(EXPORT_CFG).size > 0
  end

  # Read exported file content
  def read_export_file
    @inspec.file(EXPORT_CFG).content.to_s
  end

  # FIXED INI parser: strip sections AND values properly
  def parse_ini(text)
    out = Hash.new { |h, k| h[k] = {} }
    current = nil

    text.encode!('UTF-8', invalid: :replace, undef: :replace, replace: '')

    text.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?(';')

      if line.start_with?('[') && line.end_with?(']')
        current = line[1..-2].strip  # <-- FIXED: strip section names
        next
      end

      next unless current

      if (idx = line.index('='))
        key = line[0...idx].strip
        val = line[(idx + 1)..-1].strip  # <-- FIXED: use -1 then strip value
        out[current][key] = val
      end
    end

    out
  end

  # Fallback: System Access (Password + Lockout Policy)
  def registry_system_access
    sys = net_accounts_system_access

    # Best-effort: these exist as LSA values on many builds (but not guaranteed)
    lsa = %w[
      PasswordComplexity
      AllowAdministratorLockout
      ClearTextPassword
    ].each_with_object({}) do |k, h|
      h[k] = registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', k)
    end

    # Merge, preferring net accounts where present
    sys.merge(lsa) { |_k, a, b| a.nil? ? b : a }
  end

  # Parse `net accounts` output for password/lockout policy
  def net_accounts_system_access
    out = {}

    cmd = @inspec.command('cmd.exe /c net accounts')
    return out unless cmd && cmd.exit_status == 0

    cmd.stdout.to_s.each_line do |line|
      line = line.strip
      next if line.empty?

      # Examples (localized output may differ; this targets en-US)
      if line =~ /^Length of password history maintained:\s+(\d+)$/i
        out['PasswordHistorySize'] = Regexp.last_match(1)
      elsif line =~ /^Maximum password age\s*\(days\):\s+(.+)$/i
        out['MaximumPasswordAge'] = normalize_net_accounts_age(Regexp.last_match(1))
      elsif line =~ /^Minimum password age\s*\(days\):\s+(.+)$/i
        out['MinimumPasswordAge'] = normalize_net_accounts_age(Regexp.last_match(1))
      elsif line =~ /^Minimum password length:\s+(\d+)$/i
        out['MinimumPasswordLength'] = Regexp.last_match(1)
      elsif line =~ /^Lockout threshold:\s+(.+)$/i
        out['LockoutBadCount'] = normalize_net_accounts_number(Regexp.last_match(1))
      elsif line =~ /^Lockout duration\s*\(minutes\):\s+(.+)$/i
        out['LockoutDuration'] = normalize_net_accounts_number(Regexp.last_match(1))
      elsif line =~ /^Lockout observation window\s*\(minutes\):\s+(.+)$/i
        out['ResetLockoutCount'] = normalize_net_accounts_number(Regexp.last_match(1))
      end
    end

    out
  end

  def normalize_net_accounts_age(s)
    s = s.to_s.strip
    return '0' if s =~ /^never$/i
    normalize_net_accounts_number(s)
  end

  def normalize_net_accounts_number(s)
    s = s.to_s.strip
    return '0' if s =~ /^never$/i
    m = s.match(/(-?\d+)/)
    m ? m[1] : nil
  end

  # Registry fallback: Security Options
  def registry_security_options
    {
      'EnableAdminAccount' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'EnableAdminAccount'),
      'EnableGuestAccount' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'EnableGuestAccount'),
      'LimitBlankPasswordUse' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LimitBlankPasswordUse'),
      'SCENoApplyLegacyAuditPolicy' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa', 'SCENoApplyLegacyAuditPolicy'),
      'AddPrinterDrivers' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers', 'AddPrinterDrivers'),
      'RequireSignOrSeal' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'RequireSignOrSeal'),
      'SealSecureChannel' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'SealSecureChannel'),
      'SignSecureChannel' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'SignSecureChannel'),
      'RequireStrongKey' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters', 'RequireStrongKey'),
      'DisableCAD' => registry_read('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'DisableCAD'),
      'InactivityTimeoutSecs' => registry_read('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'InactivityTimeoutSecs'),
      'RequireSecuritySignature' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'RequireSecuritySignature'),
      'EnableSecuritySignature' => registry_read('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters', 'EnableSecuritySignature')
    }
  end

  # Registry reader (typed)
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

    # Handle registry values formatted as "type,value" (e.g., "4,1")
    if raw.include?(',')
      parts = raw.split(',')
      raw = parts[-1].strip # Take the last part (the actual value)
    end

    raw.match?(/^[-]?\d+$/) ? raw.to_i : raw
  end
end

# Resource: local_security_policy
class LocalSecurityPolicy < Inspec.resource(1)
  name 'local_security_policy'
  desc 'Reads Local Security Policy values via secedit export or registry fallback.'
  supports platform: 'windows'

  def initialize
    super()
    @policy = SeceditPolicy.new(inspec).export_and_parse || {}
  end

  # Explicit accessors for commonly used settings
  def EnableAdminAccount
    to_typed(lookup_key('EnableAdminAccount'))
  end

  def EnableGuestAccount
    to_typed(lookup_key('EnableGuestAccount'))
  end

  def LimitBlankPasswordUse
    to_typed(lookup_key('LimitBlankPasswordUse'))
  end

  def EnableServerOperatorsScheduleTasks
    to_typed(lookup_key('EnableServerOperatorsScheduleTasks'))
  end

  # Dynamic method_missing for other keys
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

  # Dynamic section scanning
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

# Ensure controls can always resolve constants, regardless of InSpec load context.
Object.const_set(:SeceditPolicy, SeceditPolicy) unless Object.const_defined?(:SeceditPolicy)
Object.const_set(:LocalSecurityPolicy, LocalSecurityPolicy) unless Object.const_defined?(:LocalSecurityPolicy)
