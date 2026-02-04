# frozen_string_literal: true

module SectionToggle
  def section_enabled?(section)
    input("run_section_#{section}", value: true)
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:SectionToggle, SectionToggle) unless Object.const_defined?(:SectionToggle)
