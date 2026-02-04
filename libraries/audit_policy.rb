# frozen_string_literal: true

class AuditPolicy < Inspec.resource(1)
  name 'audit_policy'
  desc 'Reads Windows Audit Policy categories via auditpol command.'
  supports platform: 'windows'

  def initialize
    super()
    @cache = nil
  end

  # Get audit policy settings for a specific category
  def category(category_name)
    return nil if category_name.nil?

    policies = parse_audit_policy
    return nil if policies.nil? || policies.empty?

    policies[category_name.to_s]
  end

  # Get all audit policies
  def policies
    parse_audit_policy
  end

  def to_s
    'Audit Policy'
  end

  private

  # Turn an "Inclusion Setting" string into an array of flags
  # Examples:
  #   "Success and Failure" -> ["Success", "Failure"]
  #   "Success"             -> ["Success"]
  #   "Failure"             -> ["Failure"]
  #   "No Auditing"         -> []
  #   nil / ""              -> []
  def normalize_inclusion_setting(setting)
    s = setting.to_s.strip
    return [] if s.empty?
    s_down = s.downcase

    return [] if s_down == 'no auditing'
    return ['Success', 'Failure'] if s_down == 'success and failure'
    return ['Success'] if s_down == 'success'
    return ['Failure'] if s_down == 'failure'

    # Fallback: keep raw string for troubleshooting / unexpected values
    [s]
  end

  # Parse auditpol output and return hash of categories and their settings
  # Each value is an Array of flags, or ["Mixed"] if subcategories differ.
  def parse_audit_policy
    return @cache if @cache

    @cache = {}

    # Use auditpol to get audit policy settings in "report" (CSV-like) format
    cmd = inspec.command('auditpol /get /category:* /r')
    return @cache unless cmd.exit_status == 0

    output = cmd.stdout.to_s
    return @cache if output.empty?

    lines = output.split("\n").reject(&:empty?)

    # Skip header line if present (contains "Category,Subcategory,Inclusion Setting" etc.)
    lines.shift if lines.first&.include?('Category')

    lines.each do |line|
      parts = line.split(',').map { |p| p.to_s.strip.delete('"') }
      next unless parts.length >= 3

      category          = parts[0]
      inclusion_setting = parts[2]
      next if category.empty? || inclusion_setting.empty?

      normalized_flags = normalize_inclusion_setting(inclusion_setting)

      # Aggregate settings per category; if any subcategory differs, mark as Mixed
      if @cache[category].nil?
        @cache[category] = normalized_flags
      else
        existing = @cache[category]
        unless existing == normalized_flags
          @cache[category] = ['Mixed'] unless existing.include?('Mixed')
        end
      end
    end

    @cache
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:AuditPolicy, AuditPolicy) unless Object.const_defined?(:AuditPolicy)
