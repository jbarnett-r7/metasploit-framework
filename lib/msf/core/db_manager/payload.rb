module Msf::DBManager::Payload

  def create_payload(opts)
    if opts[:uuid] && !opts[:uuid].to_s.empty?
      if Mdm::Payload.find_by(uuid: opts[:uuid])
        raise ArgumentError.new("A payload with this uuid already exists.")
      end
    end

    if ! ::File.directory?(Msf::Config.payload_directory)
      FileUtils.mkdir_p(Msf::Config.payload_directory)
    end

    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

    if opts[:file]
      file = opts.delete(:file)
      filename = File.basename(file)
      payload_path = File.join(Msf::Config.payload_directory, filename)
      FileUtils.copy(file, payload_path)
      opts[:raw_payload] = payload_path
      sha256 = Digest::SHA256.file(payload_path)
      opts[:raw_payload_hash] = sha256.hexdigest
    end

    Mdm::Payload.create(opts.merge({ workspace: wspace }))
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
        # ActiveRecord_Associations_CollectionProxy. This is because CollectionProxy uses cached values of the DB query
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

  private

  def store_payload
    if ! ::File.directory?(Msf::Config.payload_directory)
      FileUtils.mkdir_p(Msf::Config.payload_directory)
    end

    ext = 'bin'
    if filename
      parts = filename.to_s.split('.')
      if parts.length > 1 and parts[-1].length < 4
        ext = parts[-1]
      end
    end

    # This method is available even if there is no database, don't bother checking
    host = Msf::Util::Host.normalize_host(host)

    ws = (db ? myworkspace.name[0,16] : 'default')
    name =
        Time.now.strftime("%Y%m%d%H%M%S") + "_" + ws + "_" +
            (host || 'unknown') + '_' + ltype[0,16] + '_' +
            Rex::Text.rand_text_numeric(6) + '.' + ext

    name.gsub!(/[^a-z0-9\.\_]+/i, '')

    path = File.join(Msf::Config.loot_directory, name)
    full_path = ::File.expand_path(path)
    File.open(full_path, "wb") do |fd|
      fd.write(data)
    end
  end
end
