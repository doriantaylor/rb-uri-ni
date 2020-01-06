RSpec.describe URI::NI do
  it "has a version number" do
    expect(URI::NI::VERSION).not_to be nil
  end

  it 'resolves the scheme' do
    uri = URI.parse('ni:///sha-256;')
    expect(uri).to be_a(URI::NI)
  end

  # look i will write these tests when i god damn feel like it okay

  # ok we wanna test it parsing whatever (robustness principle)

  # though it should complain if you parse garbage and then try to do
  # something with it

  # it should respond to the accessors: authority, algorithm

  # it should respond to mutators with the same names as those accessors

  # `compute` should work as an instance method

  # `compute` should retrieve the algorithm from the URI or complain
  # if none present

  # `compute` should complain if the algorithm is neither already in
  # the URI nor passed in as an argument

  # `compute` should complain if the algorithm is not in the inventory

  # `compute` should work when data is nil

  # `compute` should work when data is a string

  # `compute` should work when data is an IO

  # `compute` should work when data is a Digest::Instance

  # `compute` should accept a block

  # `compute` should run the block in a read loop when data is also passed in

  # `compute` should pass the data to the block as `ctx` when data *is* ctx

  # `compute` should respond correctly to changes in blocksize

  # `compute` should work as a class method

  # `digest` without arguments should return the binary digest

  # `digest` with an unsupported radix should complain

  # `hexdigest` should do what it says on the tin

  # `hexdigest` with alt: true should be uppercase

  # `b32digest` should do what it says on the tin

  # `b32digest` with alt: true should be lowercase

  # `b64digest` should do what it says on the tin

  # `b64digest` with alt: true should be *NOT* URL-safe

  # `set_digest` should accept a Digest::Instance as an argument

  # said Digest:Instance should also update the URI's algorithm

  # `set_digest` should accept a radix

  # `set_digest` with an unsupported radix should complain

  # `set_digest` should return the original value if present

  # `set_digest` should return the original value with the same radix

  # `digest=` should behave the same as `set_digest` with radix: 256

  # `to_www` should return a URI::HTTPS representation

  # `to_www` with https: false should return a URI::HTTP

  # `to_www` with authority: String should override the URI's authority

  # `to_www` with authority: URI should pick the authority out of the URI

  # `to_https` should be the same as `to_www`

  # `to_http` should be the same as `to_www https: false`

end
