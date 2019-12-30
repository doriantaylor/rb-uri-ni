require 'uri/ni/version'
require 'uri'
require 'uri/generic'

require 'digest'
require 'base64'

class URI::NI < URI::Generic
  private

  # URI.rb has rfc2396 not 3986 so let's make an authority pattern
  AUTHORITY = "(#{URI::PATTERN::USERINFO}@)?(#{URI::PATTERN::HOST})?" \
    "(?::(#{URI::PATTERN::PORT}))?".freeze

  # this is slightly more relaxed than rfc 6920, allowing for an empty
  # value for the digest such that we can initialize ni:///algo and compute
  ALG_VAL = "([#{URI::PATTERN::UNRESERVED}]+)" \
    "(?:;([#{URI::PATTERN::UNRESERVED}]*))?".freeze

  # put it together
  PATTERN =
    "^([NnIi])://#{AUTHORITY}/#{ALG_VAL}(?:\\?#{URI::PATTERN::QUERY})?$".freeze

  # and bake it
  REGEXP = Regexp.new(PATTERN).freeze

  # map these onto upstream properties
  COMPONENT = %i[scheme userinfo host port path query]

  # resolve first against digest length and then class
  DIGEST_REV = {
    64 => { Digest::SHA512 => :"sha-512", Digest::SHA2   => :"sha-512" },
    48 => { Digest::SHA384 => :"sha-384", Digest::SHA2   => :"sha-384" },
    32 => { Digest::SHA256 => :"sha-256", Digest::SHA2   => :"sha-256" },
    20 => { Digest::RMD160 => :"rmd-160", Digest::SHA1   => :"sha-1"   },
    16 => { Digest::MD5    => :md5 },
  }

  def raw_digest
  end

  public

  # Compute an RFC6920 URI from a data source.
  # @param data [#to_s, IO, Digest, nil]
  # @param algorithm [Symbol] See algorithms
  def self.compute data = nil, algorithm: :"sha-256", blocksize: 65536,
      authority: nil, query: nil, &block
    args = { scheme: 'ni', path: "/#{algorithm}", query: query }
    obj  = build args
    return obj.compute data unless block_given?
    obj.compute(&block)
  end

  def compute data = nil, algorithm: :"sha-256", blocksize: 65536,
      authority: nil, query: nil, &block
    # data can be a digest 
  end

  def self.build args
    tmp = URI::Util.make_components_hash self, args
    super tmp
  end

  def algorithm
  end

  # Return the digest in the hash. Optionally takes a +radix:+
  # argument to specify binary, base64, base32, or hexadecimal
  # representations. Another optional flag will return alternative
  # representations for each: base64url (vanilla base64 is canonical),
  # base32 in lowercase (uppercase is canonical), hexadecimal in
  # uppercase (lowercase is canonical). The binary representation
  # naturally has no alternative form. Base64/base32 values will be
  # appropriately padded.
  #
  # @param radix [256, 64, 32, 16] The radix of the representation
  # @param alt [false, true] Return the alternative representation
  # @return [String]
  #
  def digest radix: 256
  end

  # Return the digest in its hexadecimal notation. Optionally give
  # +alt:+ a truthy value to return an alternate (uppercase)
  # representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String]
  #
  def hexdigest alt: false
  end

  # Return the digest in its base32 notation. Optionally give
  # +alt:+ a truthy value to return an alternate (lowercase)
  # representation. Note this method requires
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String]
  #
  def b32digest alt: false
    require_once 'base32'
  end

  # Return the digest in its base64 notation. Optionally give
  # +alt:+ a truthy value to return an alternate (uppercase)
  # representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String]
  #
  def b64digest alt: false
  end

  # Returns a +/.well-known/...+, either HTTPS or HTTP URL, given the
  # contents of the +ni:+ URI.
  #
  # @param authority [#to_s, URI] Override the authority part of the URI
  # @param https [true, false] whether the URL is HTTPS.
  # @return [URI::HTTPS, URI::HTTP]
  #
  def to_www https: true, authority: nil
  end

  # Unconditionally returns an HTTPS URL.
  #
  # @param authority [#to_s, URI] Override the authority part of the URI
  # @return [URI::HTTPS]
  #
  def to_https authority: nil
    # note we don't simply alias this
    to_www authority: authority
  end

  # Unconditionally returns an HTTP URL.
  #
  # @param authority [#to_s, URI] Override the authority part of the URI
  # @return [URI::HTTP]
  #
  def to_http authority: nil
    to_www https: false, authority: authority
  end


end
