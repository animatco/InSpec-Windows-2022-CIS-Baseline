
# frozen_string_literal: true

class ::AuditpolSubcategory < Inspec.resource(1)
  name 'auditpol_subcategory'
  desc 'Reads Advanced Audit Policy subcategory settings via auditpol.'
  supports platform: 'windows'

  def initialize(guid)
    super()
    @guid = guid.to_s
  end

  def inclusion_setting
    ps = %(powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "AuditPol /get /subcategory:'#{@guid}' -r | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'")
    cmd = inspec.command(ps)
    return nil unless cmd.exit_status == 0

    cmd.stdout.to_s.strip
  end

  def to_s
    "AuditPol subcategory #{@guid}"
  end
end

# Ensure controls can always resolve the constant, regardless of InSpec load context.
Object.const_set(:AuditpolSubcategory, AuditpolSubcategory) unless Object.const_defined?(:AuditpolSubcategory)
