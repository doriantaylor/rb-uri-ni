# we need this or what follows it complains
require 'uri/generic'

module URI
  class NI < Generic
    VERSION = "0.2.4"
  end

  # might as well put this here
  if self.respond_to? :register_scheme
    register_scheme 'NI', NI
  else
    @@schemes['NI'] = NI
  end
end
