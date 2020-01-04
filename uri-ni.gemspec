# -*- mode: enh-ruby -*-
require_relative 'lib/uri/ni/version'

Gem::Specification.new do |spec|
  spec.name          = 'uri-ni'
  spec.version       = URI::NI::VERSION
  spec.authors       = ['Dorian Taylor']
  spec.email         = ['code@doriantaylor.com']
  spec.license       = 'Apache-2.0'
  spec.homepage      = 'https://github.com/doriantaylor/rb-uri-ni'
  spec.summary       = 'URI handler for RFC6920 ni:/// URIs'
  spec.description = <<-DESC
  DESC

  spec.metadata['homepage_uri'] = spec.homepage

  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features)/})
    end
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # ruby
  spec.required_ruby_version = '>= 2.3.0'

  # dev/test dependencies
  spec.add_development_dependency 'bundler', '~> 2'
  # bundler put these in the gemfile i dunno wtf
  #spec.add_development_dependency 'rake',    '~> 12.0'
  #spec.add_development_dependency 'rspec',   '~> 3.0'

  # we need uri and digest and base64 but those are all in core
end
