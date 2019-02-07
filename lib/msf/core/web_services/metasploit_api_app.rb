require 'rack/cors'
require 'securerandom'
require 'sinatra/base'
require 'swagger/blocks'
require 'warden'
require 'sinatra-websocket'

require 'msf/core/web_services/authentication'
require 'msf/core/web_services/servlet_helper'
require 'msf/core/web_services/servlet/api_docs_servlet'
require 'msf/core/web_services/servlet/auth_servlet'
require 'msf/core/web_services/servlet/host_servlet'
require 'msf/core/web_services/servlet/note_servlet'
require 'msf/core/web_services/servlet/vuln_servlet'
require 'msf/core/web_services/servlet/event_servlet'
require 'msf/core/web_services/servlet/web_servlet'
require 'msf/core/web_services/servlet/msf_servlet'
require 'msf/core/web_services/servlet/workspace_servlet'
require 'msf/core/web_services/servlet/service_servlet'
require 'msf/core/web_services/servlet/session_servlet'
require 'msf/core/web_services/servlet/exploit_servlet'
require 'msf/core/web_services/servlet/loot_servlet'
require 'msf/core/web_services/servlet/session_event_servlet'
require 'msf/core/web_services/servlet/credential_servlet'
require 'msf/core/web_services/servlet/login_servlet'
require 'msf/core/web_services/servlet/nmap_servlet'
require 'msf/core/web_services/servlet/db_export_servlet'
require 'msf/core/web_services/servlet/vuln_attempt_servlet'
require 'msf/core/web_services/servlet/user_servlet'
require 'msf/core/web_services/servlet/module_search_servlet'
require 'msf/core/web_services/servlet/db_import_servlet'
require 'msf/core/web_services/servlet/update_stream_servlet'

class MetasploitApiApp < Sinatra::Base
  helpers ServletHelper

  # Servlet registration
  register ApiDocsServlet
  register AuthServlet
  register HostServlet
  register VulnServlet
  register EventServlet
  register WebServlet
  register MsfServlet
  register NoteServlet
  register WorkspaceServlet
  register ServiceServlet
  register SessionServlet
  register ExploitServlet
  register LootServlet
  register SessionEventServlet
  register CredentialServlet
  register LoginServlet
  register NmapServlet
  register DbExportServlet
  register VulnAttemptServlet
  register UserServlet
  register ModuleSearchServlet
  register DbImportServlet
  register UpdateStreamServlet

  configure do
    set :sessions, {key: 'msf-ws.session', expire_after: 300}
    set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET') { SecureRandom.hex(16) }
    set :sockets, []
  end

  before do
    # store DBManager in request environment so that it is available to Warden
    request.env['msf.db_manager'] = get_db
    # store flag indicating whether authentication is initialized in the request environment
    @@auth_initialized ||= get_db.users({}).count > 0
    request.env['msf.auth_initialized'] = @@auth_initialized

    # Monitor all requests made to the server. If it is not a read (GET) request, assume
    # something changed and inform the websocket subscribers that they need to check for
    # updates on the particular method.
    #
    # There are some obvious flaws with this:
    #  - It doesn't know if the underlying request was successful or not (but does it really matter?)
    unless request.get?
      settings.sockets.each do |ws|
        response = {}
        case request.env['REQUEST_METHOD']
        when 'POST'
          response[:action] = 'create'
        when 'DELETE'
          response[:action] = 'delete'
        when 'PUT'
          response[:action] = 'update'
        end

        response[:model] = request.env['REQUEST_PATH'].split('/').last
        # If the value is an integer the user has an ID in the path
        # Save off that ID and update the model value to be the token before the last
        #
        # TODO: This integer check won't work if there is a query string
        if response[:model].to_i.to_s == response[:model]
          response[:id] = response[:model]
          response[:model] = request.env['REQUEST_PATH'].split('/')[-2]
        end

        ws.send response.to_json
      end
    end
  end

  use Rack::Cors do
    allow do
      origins '*'

      resource '*',
               :headers => :any,
               :methods => [:get, :post, :delete, :put, :patch, :options, :head],
               :max_age => 600
    end
  end

  use Warden::Manager do |config|
    # failed authentication is handled by this application
    config.failure_app = self
    # don't intercept 401 responses since the app will provide custom failure messages
    config.intercept_401 = false
    config.default_scope = :api

    config.scope_defaults :user,
                          # whether to persist the result in the session or not
                          store: true,
                          # list of strategies to use
                          strategies: [:password],
                          # action (route) of the failure application
                          action: "#{AuthServlet.api_unauthenticated_path}/user"

    config.scope_defaults :api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:api_token],
                          # action (route) of the failure application
                          action: AuthServlet.api_unauthenticated_path

    config.scope_defaults :admin_api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:admin_api_token],
                          # action (route) of the failure application
                          action: AuthServlet.api_unauthenticated_path
  end

end
