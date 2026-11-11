# Capture Ruby's Net::HTTP fingerprint. The stdlib client links the image's
# OpenSSL, so the recorded ClientHello is what a Ruby crawler sends.
require "net/http"
require "uri"

body = Net::HTTP.get(URI("https://tls.peet.ws/api/all"))
File.binwrite(ARGV[0], body)
warn "ruby #{RUBY_VERSION}"
