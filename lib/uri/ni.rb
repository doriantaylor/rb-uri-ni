# -*- coding: utf-8 -*-
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

  def assert_radix radix
    raise ArgumentError,
      "Radix must be 16, 32, 64, or 256, not #{radix.inspect}" unless
      [256, 64, 32, 16].include? radix
    radix
  end

  # assertions about data representation
  ASSERT = {
    256 => [/.*/, ''],
    64  => [/^[0-9A-Za-z+\/_-]*=*$/, 'Data %s is not in base64'],
    32  => [/^[2-7A-Za-z]*=*$/, 'Data %s is not in base32'],
    16  => [/^[0-9A-Fa-f]*$/, 'Data %s is not in hexadecimal'],
  }

  def assert_repr data, radix
    re, error = ASSERT[radix]
    raise ArgumentError, error % data unless re.match data
  end

  # from whatever to binary
  DECODE = {
    256 => -> x { x },
    64  => -> x { Base64.decode64 x.tr('-_', '+/') },
    32  => -> x { require 'base32'; Base32.decode x },
    16  => -> x { [x].pack 'H*' },
  }

  # from binary to whatever
  ENCODE = {
    256 => -> x { x },
    64  => -> x { Base64.urlsafe_encode64(x).tr '=', '' },
    32  => -> x { require 'base32'; Base32.encode(x).tr '=', '' },
    16  => -> x { x.unpack1 'H*' },
  }

  # canonical and alternative representations
  CANON = {
    256 => -> x { x },
    64  => -> x { x.tr('=', '').tr '+/', '-_' },
    32  => -> x { x.tr('=', '').upcase },
    16  => -> x { x.downcase },
  }

  # note if we put the padding here then we sanitize input as well

  ALT = {
    256 => -> x { x },
    64  => -> x { x.tr('=', '').tr '-_', '+/' },
    32  => -> x { x.tr('=', '').downcase },
    16  => -> x { x.upcase },
  }

  def transcode data, from: 256, to: 256, alt: false
    assert_repr data, from
    data = ENCODE[to].call(DECODE[from].call data) unless from == to
    alt ? ALT[to].call(data) : CANON[to].call(data)
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
  #
  # @param data [#to_s, IO, Digest, nil]
  # @param algorithm [Symbol] See available algorithms. Default: +:"sha-256"+
  # @param blocksize [Integer] The number or bytes per call to the Digest
  # @param authority [String, nil] Optional authority (user, host, port)
  # @param query [String, nil] Optional query string
  # @yield [ctx, buf] Passes the Digest and (maybe) the buffer
  # @yieldparam ctx [Digest::Instance] The digest instance to the block
  # @yieldparam buf [String, nil] The current read buffer (if +data+ is set)
  # 
  # @return [URI::NI] 
  def self.compute data = nil, algorithm: :"sha-256", blocksize: 65536,
      authority: nil, query: nil, &block

    build({ scheme: 'ni' }).compute data, algorithm: algorithm,
      blocksize: blocksize, authority: authority, query: query, &block
  end

  
  # (Re)-compute a digest using existing information from an instance.
  # @see .compute
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
      self.algorithm = algorithm ||= self.algorithm || :"sha-256"
      raise URI::InvalidComponentError,
        "Can't resolve a Digest context for the algorithm #{algorithm}." unless
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
      ctx.base64digest.tr('+/', '-_').tr('=', ''))
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
    self.set_digest(b, radix: 64) if b
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
    assert_radix radix
    transcode raw_digest, from: 64, to: radix, alt: alt
  end

  # Set the digest to the data, with an optional radix. Data may
  # either be a +Digest::Instance+—in which case the radix is
  # ignored—a string, or +nil+. +Digest::Instance+ objects will
  # just be run through #compute, with all that entails.
  #
  # @param value [String, nil, Digest::Instance] The new digest
  # @param radix [256, 64, 32, 16] The radix of the encoding (default 256)
  # @return [String] The _old_ digest in the given radix
  #
  def set_digest value, radix: 256
    assert_radix radix

    a, d = assert_path

    case value
    when Digest::Instance
      compute value
    when String
      value = transcode value, from: radix, to: 64
      self.path = a ? "/#{a};#{value}" : "/;#{value}"
    when nil
      self.path = a ? "/#{a}" : ?/
    else
      raise ArgumentError,
        "Value must be a string or Digest::Instance, not #{value.class}"
    end

    # bail out if nil
    return unless d
    transcode d, from: 64, to: radix
  end

  # Set the digest to the data. Data may either be a
  # +Digest::Instance+ or a _binary_ string. +Digest::Instance+
  # objects will just be run through #compute, with all that entails.
  #
  # @param value [String, nil, Digest::Instance] the new digest
  # @return [String, nil, Digest::Instance] the value passed in
  #
  def digest= value
    return set_digest value
  end

  # Return the digest in its hexadecimal notation. Optionally give
  # +alt:+ a truthy value to return an alternate (uppercase)
  # representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The hexadecimal digest
  #
  def hexdigest alt: false
    transcode raw_digest, from: 64, to: 16, alt: alt
  end

  # Set the digest value, assuming a hexadecimal input.
  # @param value [String, nil, Digest::Instance] the new digest
  # @return [String, nil, Digest::Instance] the value passed in
  def hexdigest= value
    set_digest value, radix: 16
  end

  # Return the digest in its base32 notation. Optionally give
  # +alt:+ a truthy value to return an alternate (lowercase)
  # representation. Note this method requires the base32 module.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The base32 digest
  #
  def b32digest alt: false
    transcode raw_digest, from: 64, to: 32, alt: alt
  end

  # Set the digest value, assuming a base32 input (requires base32).
  # @param value [String, nil, Digest::Instance] the new digest
  # @return [String, nil, Digest::Instance] the value passed in
  def b32digest= value
    set_digest value, radix: 32
  end

  # Return the digest in its base64 notation. Note it is the
  # _default_ representation that is URL-safe, for parity with the
  # identifier itself. Give +alt:+ a truthy value to return a plain
  # (_non_-URL-safe) base64 representation.
  #
  # @param alt [false, true] Return the alternative representation
  # @return [String] The base64 digest
  #
  def b64digest alt: false
    transcode raw_digest, from: 64, to: 64, alt: alt
  end

  # Set the digest value, assuming a base64 input.
  # @param value [String, nil, Digest::Instance] the new digest
  # @return [String, nil, Digest::Instance] the value passed in
  def b64digest= value
    set_digest value, radix: 64
  end

  # Returns a +/.well-known/...+, either HTTPS or HTTP URL, given the
  # contents of the +ni:+ URI.
  #
  # @param authority [#to_s, URI] Override the authority part of the URI
  # @param https [true, false] Whether the URL is to be HTTPS.
  # @return [URI::HTTPS, URI::HTTP] The generated URL.
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
