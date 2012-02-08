require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'CheckRemoteDebuggerPresent()',
			'Description'   => %q{
					This module simply checks a pid if a debugger is present.
				},
			'License'       => MSF_LICENSE,
			'Platform'      => ['windows'],
			'SessionTypes'  => ['meterpreter'],
			'Author'        => ['MC']
		))
		register_options(
			[
				OptInt.new('PID',[false,'The PID to query.',4]),
			], self.class)
	end


	def run

		target_pid = datastore['PID']

		handle = client.railgun.kernel32.OpenProcess(PROCESS_ALL_ACCESS,TRUE,target_pid)
		retval = client.railgun.kernel32.CheckRemoteDebuggerPresent(handle['return'],1)

		if ( retval['pbDebuggerPresent'].unpack('H*').to_s == "01" )
			print_error("Process is being debugged!")
		else
			print_good("Not being debugged.")
		end

	end
end
