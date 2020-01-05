# we need this or what follows it complains
require 'uri/generic'

module URI
  class NI < Generic
    VERSION = "0.1.1"
  end

  # might as well put this here
  @@schemes['NI'] = NI
end
