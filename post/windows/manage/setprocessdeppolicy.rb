require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	
	def initialize(info={})
		super( update_info( info,
				'Name'          => 'SetProcessDEPPolicy',
				'Description'   => %q{Sets DEP(permanent)}, 
				'License'       => MSF_LICENSE,
				'Author'        => [ 'MC' ],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

	end

	def run

		client.railgun.add_function('kernel32', 'SetProcessDEPPolicy', 'BOOL',[["DWORD","dwFlags","in"]])

		dep = client.railgun.kernel32.SetProcessDEPPolicy(0x00000001)
		name = client.sys.process.open
		print_status("DEP enabled for '#{name.name}'!")

	end

end
