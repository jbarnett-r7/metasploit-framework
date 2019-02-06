require 'sinatra-websocket'

module UpdateStreamServlet
  def self.ws_path
    '/api/v1/update_stream'
  end

  def self.registered(app)
    app.get UpdateStreamServlet.ws_path do
      if !request.websocket?
        # This erb file is just for testing
        erb :websockets_test2
      else
        request.websocket do |ws|
          ws.onopen do
            ws.send("Hello world")
            settings.sockets << ws
          end

          ws.onmessage do |msg|
            EM.next_tick { settings.sockets.each { |s| s.send(msg) } }
          end

          ws.onclose do
            warn("websocket closed")
            settings.sockets.delete(ws)
          end
        end
      end

    end
  end
end
