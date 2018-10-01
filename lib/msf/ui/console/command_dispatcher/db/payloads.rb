# -*- coding: binary -*-

require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'
require 'digest'

module Msf
module Ui
module Console
module CommandDispatcher

module Payloads
  @@payload_columns = nil

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

    opts = { order_by: 0, search_opts: {}, add_opts: {} }
    mode = nil
    while (arg = args.shift)
      case arg
        when '-a','--add'
          mode = :add
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
        when '-d','--description'
          opts[:add_opts][:description] = args.shift
        when '-D','--delete'
          mode = :delete
        when '-f','--file'
          opts[:add_opts][:file] = args.shift
        when '-n','--name'
          opts[:add_opts][:name] = args.shift
        when '-O','--order-by'
          if (opts[:order_by] = args.shift.to_i - 1) < 0
            print_error('Please specify a column number starting from 1')
            return
          end
        when '-p','--platform'
          opts[:add_opts][:platform] = args.shift
        when '-r','--arch'
          opts[:add_opts][:arch] = args.shift
        when '-S','-search'
          opts[:search_opts][:search_term] = args.shift
      end
    end

    if mode == :add
      add_payload(opts)
    end
    payloads = payloads_search(opts[:search_opts])
    display_payloads(payloads, opts)
    if mode == :delete
      delete_opts = {}
      delete_opts[:ids] = payloads.map { |p| p.id }
      deleted = framework.db.delete_payload(delete_opts)
      print_status "Deleted #{deleted.count} payloads." if deleted.size > 0
    end
  end

  def cmd_payloads_help
    print_line "Usage: payloads [ options ]"
    print_line
    print_line "OPTIONS:"
    print_line "  -c <col1,col2>    Only show the given columns (see list below)"
    print_line "  -C <col1,col2>    Only show the given columns until the next restart (see list below)"
    print_line "  -S,--search       Search string to filter by"
    print_line "  -h,--help         Show this help information"
    print_line
    print_line "Available columns: #{default_columns.join(", ")}"
    print_line
    return
  end

  def display_payloads(payloads, opts)
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

    payloads.each do |payload|
      columns = col_names.map { |n| payload[n].to_s || "" }
      tbl << columns
    end

    print_line(tbl.to_s)
  end

  def payloads_search(search_opts)
    search_opts[:workspace] = framework.db.workspace
    framework.db.payloads(search_opts)
  end

  def add_payload(opts)
    if opts[:add_opts][:file].nil? || (opts[:add_opts][:file].is_a?(String) && opts[:add_opts][:file].empty?)
      print_error "A payload file is required. Please specify one with the -f option."
      print_line
      return
    end
    unless File.exists?(opts[:add_opts][:file])
      print_error "Unable to locate the payload file at #{opts[:add_opts][:file]}"
      print_line
      return
    end

    opts[:add_opts][:workspace] = framework.db.workspace
    framework.db.create_payload(opts[:add_opts])
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
