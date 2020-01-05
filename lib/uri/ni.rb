require 'uri/ni/version'
require 'uri'
require 'uri/generic'

require 'digest'
require 'base64'
require 'stringio'

class URI::NI < URI::Generic
  private

  # URI.rb has rfc2396 not 3986 so let's make an authority pattern
  AUTHORITY = "(#{URI::PATTERN::USERINFO}@)?(#{URI::PATTERN::HOST})?" \
    "(?::(#{URI::PATTERN::PORT}))?".freeze

  AUTH_RE = /^#{AUTHORITY}$/o.freeze
  HOST_RE = /^#{URI::PATTERN::HOST}?$/o.freeze

  # this is slightly more relaxed than rfc 6920, allowing for an empty
  # value for the digest such that we can initialize ni:///algo and compute
  ALG_VAL = "([#{URI::PATTERN::UNRESERVED}]+)" \
    "(?:;([#{URI::PATTERN::UNRESERVED}]*))?".freeze

  PATH    = "/(?:#{ALG_VAL})?".freeze
  PATH_RE = /^(?:#{PATH})?$/o.freeze

  # put it together
  PATTERN =
    "^([NnIi])://#{AUTHORITY}/#{ALG_VAL}(?:\\?#{URI::PATTERN::QUERY})?$".freeze

  # and bake it
  REGEXP = Regexp.new(PATTERN).freeze

  # map these onto upstream properties
  COMPONENT = %i[scheme userinfo host port path query]

  DIGESTS = {
    "md5":     Digest::MD5,
    "rmd-160": Digest::RMD160,
    "sha-1":   Digest::SHA1,
    "sha-256": Digest::SHA256,
    "sha-384": Digest::SHA384,
    "sha-512": Digest::SHA512,
  }

  # resolve first against digest length and then class
  DIGEST_REV = {
    64 => { Digest::SHA512 => :"sha-512", Digest::SHA2   => :"sha-512" },
    48 => { Digest::SHA384 => :"sha-384", Digest::SHA2   => :"sha-384" },
    32 => { Digest::SHA256 => :"sha-256", Digest::SHA2   => :"sha-256" },
    20 => { Digest::RMD160 => :"rmd-160", Digest::SHA1   => :"sha-1"   },
    16 => { Digest::MD5    => :md5 },
  }

  def algo_for ctx, algo = nil
    raise NotImplementedError, "Unknown digest type #{ctx.class}" unless
      d = DIGEST_REV[ctx.digest_length] and d[ctx.class]
    raise ArgumentError,
      "algorithm #{algo} does not match digest type #{ctx.class}" if
      algo and algo != d[ctx.class]
    d[ctx.class]
  end

  def raw_digest
    PATH_RE.match(path).captures[1] || ''
  end

  def assert_authority authority = nil
    authority ||= self.authority
    m = AUTH_RE.match(authority) or raise ArgumentError,
      "Invalid authority #{authority}"
    m.captures
  end

  def assert_path path = nil
    path ||= self.path
    m = PATH_RE.match(path) or raise ArgumentError,
      "Path #{path} does not match constraint"
    m.captures
  end

  protected

  # holy crap you can override these?

  # our host can be an empty string
  def check_host host
    !!HOST_RE.match(host)
  end

  # our path has constraints
  def check_path path
    !!PATH_RE.match(path)
  end

  # make sure the host is always set to the empty string
  def set_host v
    @host = v.to_s
  end

  public

  # Compute an RFC6920 URI from a data source.
  # @param data [#to_s, IO, Digest, nil]
  # @param algorithm [Symbol] See algorithms
  def self.compute data = nil, algorithm: :"sha-256", blocksize: 65536,
      authority: nil, query: nil, &block

    build({ scheme: 'ni' }).compute data, algorithm: algorithm,
      blocksize: blocksize, authority: authority, query: query, &block
  end

  def compute data = nil, algorithm: nil, blocksize: 65536,
      authority: nil, query: nil, &block

    # enforce block size
    raise ArgumentError,
      "Blocksize must be an integer >0, not #{blocksize}" unless
      blocksize.is_a? Integer and blocksize > 0

    # special case for when the data is a digest
    ctx = nil
    if data.is_a? Digest::Instance
      algorithm ||= algo_for data, algorithm
      ctx  = data
      data = nil # unset data
    else
      # make sure we're all on the same page hurr
      self.algorithm = algorithm ||= self.algorithm
      raise URI::InvalidComponentError,
        "#{algorithm} is not a supported digest algorithm." unless
        ctx = DIGESTS[algorithm]
      ctx = ctx.new
    end

    # deal with authority component
    if authm = AUTH_RE.match(authority.to_s)
      userinfo, host, port = authm.captures
      set_userinfo userinfo
      set_host     host.to_s
      set_port     port
    end

    # coerce data to something non-null
    data = data.to_s if (data.class.ancestors & [String, IO, NilClass]).empty?
    if data
      data = StringIO.new data unless data.is_a? IO

      # give us a default block
      block ||= -> x, y { x << y } # unless block_given?

      while buf = data.read(blocksize)
        block.call ctx, buf
      end
    elsif block
      block.call ctx, nil
    end

    self.set_path("/#{algorithm};" +
      ctx.base64digest.gsub(/[+\/]/, ?+ => ?-, ?/ => ?_).gsub(/=/, ''))

    self
  end

  # Display the available algorithms.
  #
  # @return [Array] containing the symbols representing the available
  #  digest algorithms.
  def self.algorithms
    DIGESTS.keys.sort
  end

  # Obtain the algorithm of the digest. May be nil.
  #
  # @return [Symbol, nil]
  def algorithm
    algo = assert_path.first
    return algo.to_sym if algo
  end

  # Set the algorithm of the digest. Will croak if the path is malformed.
  #
  # @return [Symbol, nil] the old algorithm
  def algorithm= algo
    a, b = assert_path
    self.path   = "/#{algo}"
    self.digest = b if b
    a.to_sym if a
  end

  # Obtain the authority (userinfo@host:port) if present.
  #
  # @return [String, nil] the authority
  def authority
    out = userinfo ? "#{userinfo}@#{host}" : host
    out += "#{out}:#{port}" if port
    out
  end

  # Set the authority of the URI.
  #
  # @return [String, nil] the old authority
  def authority= authority
    old = self.authority
    u, h, p = assert_authority authority unless authority.nil?
    set_userinfo u
    set_host     h
    set_port     p
    old
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
  # @return [String] The digest of the URI in the given representation
  #
  def digest radix: 256, alt: false
    case radix
    when 256
      # XXX do not use urlsafe_decode64; it will complain if the
      # thingies aren't aligned
      Base64.decode64(raw_digest.tr('-_', '+/'))
    when 64
      b64digest alt: alt
    when 32
      b32digest alt: alt
    when 16
      hexdigest alt: alt
    else
      raise ArgumentError, "Radix must be 16, 32, 64, 256, not #{radix}"
    end
  end

  # Set the digest to the data. Data may either be a
  # +Digest::Instance+ or a base64 string. String representations will
  # be normalized to {https://tools.ietf.org/html/rfc3548#section-4
  # RFC 3548} base64url, i.e. +\+/+ will be replaced with +-_+ and
  # padding (+=+) will be removed. +Digest::Instance+ objects will
  # just be run through #compute, with all that entails.
  def digest= data
    a = assert_path.first
    case data
    when Digest::Instance
      compute data
    when String
      raise ArgumentError, "Data #{data} is not in base64" unless
        /^[0-9A-Za-z+\/_-]*=*$/.match(data)
      data = data.tr('+/', '-_').tr('=', '')
      self.path = a ? "/#{a};#{data}" : "/;#{data}"
    when nil
      self.path = a ? "/#{a}" : ?/
    else
      raise ArgumentError,
        "Data must be a string or Digest::Instance, not #{data.class}"
    end

    data
  end

  # Return the digest in its hexadecimal notation. Optionally give
  # +alt:+ a truthy value to return an alternate (uppercase)
  # representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The hexadecimal digest
  #
  def hexdigest alt: false
    str = digest.unpack('H*').first
    return str.upcase if alt
    str
  end

  # Return the digest in its base32 notation. Optionally give
  # +alt:+ a truthy value to return an alternate (lowercase)
  # representation. Note this method requires
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The base32 digest
  #
  def b32digest alt: false
    require 'base32'
    ret = Base32.encode(digest).gsub(/=+/, '')
    return ret.downcase if alt
    ret.upcase
  end

  # Return the digest in its base64 notation. Optionally give
  # +alt:+ a truthy value to return an alternate (URL-safe)
  # representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The base64 digest
  #
  def b64digest alt: false
    ret = raw_digest
    return ret.gsub(/[-_]/, ?- => ?+, ?_ => ?/) unless alt
    ret
  end

  # Returns a +/.well-known/...+, either HTTPS or HTTP URL, given the
  # contents of the +ni:+ URI.
  #
  # @param authority [#to_s, URI] Override the authority part of the URI
  # @param https [true, false] whether the URL is to be HTTPS.
  # @return [URI::HTTPS, URI::HTTP]
  #
  def to_www https: true, authority: nil
    a, d = assert_path
    components = {
      scheme:   "http#{https ? ?s : ''}",
      userinfo: userinfo,
      host:     host,
      port:     port,
      path:     "/.well-known/ni/#{a}/#{d}",
      query:    query,
      fragment: fragment,
    }

    if authority
      uhp = []
      if authority.is_a? URI
        raise URI::InvalidComponentError, "Bad authority #{authority}" unless
          %i[userinfo host port].all? {|c| authority.respond_to? c }
        uhp = [authority.userinfo, authority.host, authority.port]
        uhp[2] = nil if authority.port == authority.class::DEFAULT_PORT
      else
        authority = authority.to_s
        uhp = AUTH_RE.match(authority) or raise URI::InvalidComponentError,
          "Invalid authority #{authority}"
        uhp = uhp.captures
      end
      components[:userinfo] = uhp[0]
      components[:host]     = uhp[1]
      components[:port]     = uhp[2]
    end

    # pick the class
    cls = https ? URI::HTTPS : URI::HTTP

    # `normalize` should do this but doesn't
    components[:port] = nil if
      components[:port] and components[:port] == cls::DEFAULT_PORT

    cls.build(components).normalize
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
