module Msf::DBManager::Payload

  def create_payload(opts)
    if opts[:uuid] && !opts[:uuid].to_s.empty?
      if Mdm::Payload.find_by(uuid: opts[:uuid])
        raise ArgumentError.new("A payload with this uuid already exists.")
      end
    end

    Mdm::Payload.create(opts)
  end

  def payloads(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Payload.find(opts[:id]))
      end

      search_term = opts.delete(:search_term)

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Payload, search_term)
        wspace.payloads.where(opts).where(column_search_conditions)
      else
        # The .order call is a hack to ensure that an ActiveRecord_AssociationRelation is created instead of an
        # ActiveRecord_Associations_CollectionProxy. This is because CollectionProxy uses cached values of the query
        # unless .reload is explicitly called, which can make the results from this object inconsistent with what is expected.
        wspace.payloads.where(opts).order(:id)
      end
    end
  end

  def update_payload(opts)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace

      id = opts.delete(:id)
      Mdm::Payload.update(id, opts)
    end
  end

  def delete_payload(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection do
      deleted = []
      opts[:ids].each do |payload_id|
        payload = Mdm::Payload.find(payload_id)
        begin
          deleted << payload.destroy
        rescue
          elog("Forcibly deleting #{payload}")
          deleted << payload.delete
        end
      end

      return deleted
    end
  end

end
