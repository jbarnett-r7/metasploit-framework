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

    opts = { order_by: 0 }
    while (arg = args.shift)
      case arg
        when '-c','-C'
          list = args.shift
          if(!list)
            print_error("Invalid column list")
            return
          end
          col_search = list.strip.split(",")
          col_search.each { |c|
            if not default_columns.include?(c) and not extra_columns.include?(c)
              all_columns = default_columns + extra_columns
              print_error("Invalid column list. Possible values are (#{all_columns.join("|")})")
              return
            end
          }
          if (arg == '-C')
            @@payload_columns = col_search
          end
          opts[:col_search] = col_search
        when '-O','--order-by'
          if (opts[:order_by] = args.shift.to_i - 1) < 0
            print_error('Please specify a column number starting from 1')
            return
          end
      end
    end

    payloads_search(opts)
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

  def payloads_search(opts)
    col_names = default_columns
    if @@payload_columns
      col_names = @@payload_columns
    end
    if opts[:col_search]
      col_names = opts[:col_search]
    end

    tbl = Rex::Text::Table.new({
                                   'Header'    => "Payloads",
                                   'Columns'   => col_names,
                                   'SortIndex' => opts[:order_by]
                               })

    payloads = framework.db.payloads(workspace: framework.db.workspace)

    payloads.each do |payload|
      columns = col_names.map { |n| payload[n].to_s || "" }
      tbl << columns
    end

    print_line(tbl.to_s)
  end

  private

  def default_columns
    [ 'name', 'uuid', 'arch', 'platform', 'description']
  end

  def extra_columns
    [ 'timestamp', 'urls', 'raw_payload_hash', 'build_opts']
  end
end

end end end end
