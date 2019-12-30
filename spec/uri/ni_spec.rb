RSpec.describe URI::NI do
  it "has a version number" do
    expect(URI::NI::VERSION).not_to be nil
  end

  it 'resolves the scheme' do
    uri = URI.parse('ni:///sha-256;')
    expect(uri).to be_a(URI::NI)
  end

end
