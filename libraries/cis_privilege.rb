# frozen_string_literal: true

module CisPrivilege
  def self.normalize(list)
    return [] if list.nil?
    Array(list).map(&:to_s).map(&:strip).map(&:upcase)
  end

  def self.includes?(actual_list, expected)
    actual = normalize(actual_list)
    exp    = normalize(expected)
    exp.all? { |e| actual.include?(e) }
  end

  def self.empty?(actual_list)
    normalize(actual_list).empty?
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:CisPrivilege, CisPrivilege) unless Object.const_defined?(:CisPrivilege)
