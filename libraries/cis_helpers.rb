# frozen_string_literal: true

module CisHelpers
  def self.cis_password_age_days(value)
    return nil if value.nil?
    value.to_i / 86_400
  end
end

# Make the constant resolvable from controls regardless of InSpec load context.
Object.const_set(:CisHelpers, CisHelpers) unless Object.const_defined?(:CisHelpers)
