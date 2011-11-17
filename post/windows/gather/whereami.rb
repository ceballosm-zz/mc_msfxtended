require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Identify What Process Space Where Are In',
				'Description'   => %q{ This module identifies what process where are in.  },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'MC' ],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run

		name = client.sys.process.open
		print_status("All up in the process space of '#{name.name}'!")

	end
end
