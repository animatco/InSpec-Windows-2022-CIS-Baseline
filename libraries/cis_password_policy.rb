# frozen_string_literal: true

###############################################
# CIS Microsoft Windows Server 2022 Benchmark
# Section 01 — Account Policies
###############################################

# Updated CisPasswordPolicy library for LOCAL POLICY:
# - secedit/net accounts already use DAYS for age and MINUTES for lockout.
# - Do NOT divide by SECONDS_PER_DAY or SECONDS_PER_MINUTE here.

module CisPasswordPolicy
  # ---- Numeric converters -----------------------------------------------------

  # Returns Integer days or nil if value is nil.
  # secedit: MaximumPasswordAge, MinimumPasswordAge are in DAYS.
  def self.max_age_days(value)
    return nil if value.nil?
    value.to_i        # e.g. "90" -> 90 days
  end

  # Returns Integer days or nil if value is nil.
  def self.min_age_days(value)
    return nil if value.nil?
    value.to_i        # e.g. "0" -> 0 days
  end

  # Returns Integer minutes or nil if value is nil.
  # secedit/net accounts: LockoutDuration, ResetLockoutCount are in MINUTES.
  def self.lockout_minutes(value)
    return nil if value.nil?
    value.to_i        # e.g. "30" -> 30 minutes
  end

  # Returns Integer minutes or nil if value is nil.
  def self.reset_lockout_minutes(value)
    return nil if value.nil?
    value.to_i        # e.g. "30" -> 30 minutes
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
    value.to_i == 1   # 1 = Enabled
  end

  # Returns true when reversible encryption is disabled, false when enabled,
  # or nil if policy not present.
  def self.reversible_encryption_disabled?(value)
    return nil if value.nil?
    value.to_i == 0   # 0 = Disabled
  end

  # Returns true/false, or nil if policy not present.
  def self.admin_lockout_enabled?(value)
    return nil if value.nil?
    value.to_i == 1   # 1 = Enabled
  end

  # ---- Presence / configuration helpers --------------------------------------

  # Generic "configured" check: not nil and not empty string.
  def self.configured?(value)
    !value.nil? && !(value.respond_to?(:empty?) && value.empty?)
  end

  # For controls where 0 means "not configured" or "unlimited"
  # (e.g., CIS wants > 0).
  def self.configured_nonzero?(value)
    return false if value.nil?
    value.to_i != 0
  end
end

# Ensure controls can resolve the constant regardless of InSpec load context.
Object.const_set(:CisPasswordPolicy, CisPasswordPolicy) unless Object.const_defined?(:CisPasswordPolicy)
