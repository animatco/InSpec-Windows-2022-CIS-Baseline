# frozen_string_literal: true

class AuditPolicy < Inspec.resource(1)
  name 'audit_policy'
  desc 'Reads Windows Audit Policy categories via auditpol command.'
  supports platform: 'windows'

  def initialize
    super()
    @cache = nil
  end

  #
  # Get audit policy settings for a specific category
  #
  def category(category_name)
    return nil if category_name.nil?

    policies = parse_audit_policy
    return nil if policies.nil? || policies.empty?

    policies[category_name.to_s]
  end

  #
  # Get all audit policies
  #
  def policies
    parse_audit_policy
  end

  def to_s
    'Audit Policy'
  end

  private

  #
  # Parse auditpol output and return hash of categories and their settings
  #
  def parse_audit_policy
    return @cache if @cache

    @cache = {}

    # Use auditpol to get audit policy settings in CSV format
    ps = 'auditpol /get /category:* /r'
    cmd = inspec.command(ps)

    return @cache unless cmd.exit_status == 0

    output = cmd.stdout.to_s
    return @cache if output.empty?

    # Parse CSV output line by line
    lines = output.split("\n").reject(&:empty?)

    # Skip header line if present
    lines.shift if lines.first&.include?('Category')

    lines.each do |line|
      parts = line.split(',').map { |p| p.to_s.strip.gsub('"', '') }
      next unless parts.length >= 3

      category = parts[0]
      inclusion_setting = parts[2]

      next if category.empty? || inclusion_setting.empty?

      # Aggregate settings per category (all subcategories must match for category to be set)
      if @cache[category].nil?
        @cache[category] = inclusion_setting
      else
        # If any subcategory differs, mark as mixed
        existing = @cache[category].to_s
        unless existing == inclusion_setting
          @cache[category] = "Mixed" unless existing.include?("Mixed")
        end
      end
    end

    @cache
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:AuditPolicy, AuditPolicy) unless Object.const_defined?(:AuditPolicy)
