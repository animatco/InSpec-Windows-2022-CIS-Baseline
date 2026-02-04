# frozen_string_literal: true

###############################################
# CIS Microsoft Windows Server 2022 Benchmark
# Section 01 — Account Policies
###############################################

# Updated CisPasswordPolicy library with stronger nil/zero handling

module CisPasswordPolicy
  SECONDS_PER_DAY    = 86_400
  SECONDS_PER_MINUTE = 60

  # ---- Numeric converters -----------------------------------------------------

  # Returns Integer days or nil if value is nil.
  # 0 days is a valid value here, so do not special-case it.
  def self.max_age_days(value)
    return nil if value.nil?
    value.to_i / SECONDS_PER_DAY
  end

  # Returns Integer days or nil if value is nil.
  def self.min_age_days(value)
    return nil if value.nil?
    value.to_i / SECONDS_PER_DAY
  end

  # Returns Integer minutes or nil if value is nil.
  def self.lockout_minutes(value)
    return nil if value.nil?
    value.to_i / SECONDS_PER_MINUTE
  end

  # Returns Integer minutes or nil if value is nil.
  def self.reset_lockout_minutes(value)
    return nil if value.nil?
    value.to_i / SECONDS_PER_MINUTE
  end

  # Returns Integer threshold or nil if value is nil.
  def self.lockout_threshold(value)
    return nil if value.nil?
    value.to_i
  end

  # ---- Boolean interpreters ---------------------------------------------------

  # Returns true/false, or nil if policy not present.
  def self.complexity_enabled?(value)
    return nil if value.nil?
    value.to_i == 1
  end

  # Returns true when reversible encryption is disabled, false when enabled,
  # or nil if policy not present.
  def self.reversible_encryption_disabled?(value)
    return nil if value.nil?
    value.to_i == 0
  end

  # Returns true/false, or nil if policy not present.
  def self.admin_lockout_enabled?(value)
    return nil if value.nil?
    value.to_i == 1
  end

  # ---- Presence / configuration helpers --------------------------------------

  # Generic "configured" check: not nil and not empty string.
  def self.configured?(value)
    !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
  end

  # For controls where 0 means "not configured" or "unlimited" (e.g., CIS wants > 0).
  def self.configured_nonzero?(value)
    return false if value.nil?
    value.to_i != 0
  end
end

# Ensure controls can resolve the constant regardless of InSpec load context.
Object.const_set(:CisPasswordPolicy, CisPasswordPolicy) unless Object.const_defined?(:CisPasswordPolicy)
