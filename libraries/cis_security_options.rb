# frozen_string_literal: true

module CisSecurityOptions
  def self.to_bool(value)
    return false if value.nil?
    v = value.to_s.strip
    return true  if v == '1' || v.casecmp('enabled').zero?
    return false if v == '0' || v.casecmp('disabled').zero?
    false
  end

  def self.enabled?(value)
    to_bool(value) == true
  end

  def self.disabled?(value)
    to_bool(value) == false
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:CisSecurityOptions, CisSecurityOptions) unless Object.const_defined?(:CisSecurityOptions)
