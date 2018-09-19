# -*- coding: binary -*-

require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'

module Msf
module Ui
module Console
module CommandDispatcher

module Payloads
  #
  # Returns the hash of commands supported by this dispatcher.
  #
  def commands_payload
    {
        "payloads" => "List all payloads in the database"
    }
  end

  def cmd_payloads(*args)
    return unless active?

    # Short-circuit help
    if args.delete("-h") || args.delete("--help")
      cmd_payloads_help
      return
    end
  end

  def cmd_payloads_help
    print_line "Usage: payloads [ options ]"
    print_line
    print_line "OPTIONS:"
    print_line "  -c <col1,col2>    Only show the given columns (see list below)"
    print_line "  -C <col1,col2>    Only show the given columns until the next restart (see list below)"
    print_line "  -h,--help         Show this help information"
    print_line
    print_line "Available columns: #{default_columns.join(", ")}"
    print_line
    return
  end

  def payloads_search(*args)

  end

  private

  def default_columns
    [ 'name', 'uuid', 'arch', 'platform', 'description']
  end
end

end end end end
