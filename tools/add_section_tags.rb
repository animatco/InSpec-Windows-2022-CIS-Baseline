
#!/usr/bin/env ruby
# Automatically insert `tag section: 'X.Y'` into CIS controls.
# Supports:
#   - Running on all controls (default)
#   - Running on specific files (ARGV)
#   - Idempotent insertion (never duplicates tags)

require 'fileutils'

# If files are passed as arguments, process only those.
# Otherwise, process all controls.
target_files = ARGV.empty? ? Dir.glob("controls/*.rb") : ARGV

# Matches control 'cis-2.2.3' or control "cis-18.9.12.1"
CONTROL_REGEX = /^control\s+['"]cis-(\d+\.\d+)[^'"]*['"]/
TAG_REGEX     = /^\s*tag\s+section:/

target_files.each do |file|
  lines = File.readlines(file)
  changed = false
  output = []

  current_section = nil
  inside_control = false
  tag_inserted = false

  lines.each_with_index do |line, idx|
    # Detect control start and extract section prefix
    if line =~ CONTROL_REGEX
      inside_control = true
      tag_inserted = false
      current_section = $1 # e.g., "2.2", "18.9"
    end

    # Detect existing tag
    if inside_control && line =~ TAG_REGEX
      tag_inserted = true
    end

    output << line

    # Insert tag after title or immediately after control line
    if inside_control && !tag_inserted
      if line.strip.start_with?("title ") || line.strip.start_with?("desc ")
        output << "  tag section: '#{current_section}'\n"
        tag_inserted = true
        changed = true
      elsif line =~ CONTROL_REGEX && !lines[idx + 1].strip.start_with?("title")
        # No title present, insert right after control line
        output << "  tag section: '#{current_section}'\n"
        tag_inserted = true
        changed = true
      end
    end

    # Detect end of control block
    if inside_control && line.strip == "end"
      inside_control = false
      current_section = nil
    end
  end

  if changed
    puts "Updated: #{file}"
    File.write(file, output.join)
  else
    puts "No changes: #{file}"
  end
end
