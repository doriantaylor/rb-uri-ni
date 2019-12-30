require 'uri/ni/version'
require 'uri'
require 'uri/generic'

class URI::NI < ::URI::Generic
  private

  COMPONENT = %i[scheme authority algorithm digest query]

  public

  # 
  def self.compute data = nil, algorithm: :"sha-256", query: nil, &block
  end



end
