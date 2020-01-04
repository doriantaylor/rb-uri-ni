# URI::NI - RFC6920 Named Identifiers

This module implements the `ni:` URI scheme from [RFC
6920](https://tools.ietf.org/html/rfc6920).

```ruby
require 'uri'
require 'uri-ni' # or 'uri/ni', if you prefer

ni = URI::NI.compute 'some data'
# => #<URI::NI ni:///sha-256;EweZDmulyhRes16ZGCqb7EZTG8VN32VqYCx4D6AkDe4>
ni.hexdigest
# => "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee"
```

This of course corresponds to:

```bash
$ echo -n some data | sha256sum
1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee  -
```

This works as expected:

```ruby
ni = URI('ni:///sha-256;4wwup6dvg7fBqXXdwkKGtnXnFOu7xyzNXwQBcwIxq1c')
# => #<URI::NI ni:///sha-256;4wwup6dvg7fBqXXdwkKGtnXnFOu7xyzNXwQBcwIxq1c>
```

RFC 6920 [specifies a
registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
for algorithm designators. Of that list, `sha-256`, `sha-384` and
`sha-512` are implemented. Eventually I will get around to doing the
SHA-3 digests as well as the truncated SHA-256 ones. Implemented but
_not_ in the registry are `md5`, `sha-1` and `rmd-160`. Really these
identifiers only matter when you are trying to `compute` a new
digest. For instance you can do this:

```ruby
ni = URI('ni:///lol;wut')
# => #<URI::NI ni:///lol;wut>
```

…and the parser won't complain. But, if you then tried to take this
result and compute a new digest with it:

```ruby
ni
# => #<URI::NI ni:///lol;wut>
ni.compute 'derp'
ArgumentError: lol is not a supported digest algorithm.
```

Similarly, the digest component of the URI can be anything going in to
the parser, but only base64 is valid for subsequent manipulation:

```
ni.digest = '$#!%$%'
ArgumentError: Data $#!%$% is not in base64
```

In addition to computing new digest URIs, this module will return the
interesting part of its contents in binary, base64, hexadecimal, and
(with a soft dependency), [base32](https://rubygems.org/gems/base32).

Finally, this module will also reuse any extant `Digest::Instance`
object as long as it is in the inventory, and furthermore the
`compute` method takes a block:

```ruby
ctx = Digest::SHA256.new
# => #<Digest::SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855>
ctx << 'hello world'
# => #<Digest::SHA256: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9>
ni = URI::NI.compute ctx
# => #<URI::NI ni:///sha-256;uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek>
ni.hexdigest
# => "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
ni = URI::NI.compute do |ctx|
  ctx << 'hello world'
end
# => #<URI::NI ni:///sha-256;uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek>
```

## Documentation

Generated and deposited [in the usual
place](http://www.rubydoc.info/github/doriantaylor/rb-uri-ni/master).

## Installation

You know how to do this:

    $ gem install uri-ni

Or, [download it off rubygems.org](https://rubygems.org/gems/uri-ni).

## Contributing

Bug reports and pull requests are welcome at
[the GitHub repository](https://github.com/doriantaylor/rb-uri-ni).

## Copyright & License

©2019 [Dorian Taylor](https://doriantaylor.com/)

This software is provided under
the [Apache License, 2.0](https://www.apache.org/licenses/LICENSE-2.0).
