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
