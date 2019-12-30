# we need this or what follows it complains
require 'uri/generic'

module URI
  class NI < ::URI::Generic
    VERSION = "0.1.0"
  end

  # might as well put this here
  @@schemes['NI'] = NI
end
