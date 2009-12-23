#!/usr/bin/ruby

require 'pcaplet'
require 'ipaddr'
require 'rubygems'
require 'ruby-debug'
require 'optparse'
require 'socket'

class Anne

	$hosts = Array.new
	$network = Pcaplet.new('-s 1500')

	$filter = Pcap::Filter.new('ip', $network.capture)

	$network.add_filter($filter)


	# ------------------------------------------------------------------------------- #
	@@cmds = Array.[]({ :name => "help", :help => "Help about help? Are you nuts?" } ,
			  { :name => "quit", :help => "Will quit the program." } , 
			  { :name => "hosts", :help => "Display a list of the other hosts on the network." },
			  { :name => "listen", :help => "Listen for stuff."},
			  { :name => "info", :help => "Display everything I've discovered so far." })

	@@listens = Array.[]({ :name => "hosts", :method => "listen_hosts"})
	# ------------------------------------------------------------------------------- #


	def banner()
		puts "[ Awesome Network eNumeration & Exploration v0.1 ] "
	end

	def help( help_on )
		if help_on.nil?
			yield
		else
			@@cmds.each do |cmd|
				if cmd[:name] == help_on
					puts cmd[:help]
					break
				elsif cmd == @@cmds.last
					yield
				end
			end
		end

	end

	def quit()
		print "Are you sure you want to quit? (Y/N): "
		response = gets
		if response.chomp == "y" || response.chomp == "Y"
			puts "Quitting!"
			exit
		else return
		end
	end

	def check_for_doubles(ip)
		$hosts.each do |host|
			if host[:ip_address] == ip
				return 1
			end     
		end
		return 0
	end

	def get_my_ip()
		orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true

		UDPSocket.open do |s|
			s.connect '64.233.187.99', 1
			return s.addr.last
		end
	ensure
		Socket.do_not_reverse_lookup = orig
	end

	def put_host_list()
		puts "Host list:"
		$hosts.each do |host|
			puts host[:ip_address]
		end
	end

	def info()
		puts "Your IP: " << get_my_ip
		if !$hosts.empty?
			put_host_list
		end
	end


	def listen_handler( listen_type )
		if listen_type.nil?
			yield
		else
			@@listens.each do |listen|
				if listen[:name] == listen_type
					puts "\nListening for #{listen_type}"
					listen_hosts()
				elsif listen == @@listens.last
					puts "\nCan't listen for '#{listen_type}'"
				end
			end
		end
		return
	end
	

	def listen_hosts()
		thread = Thread.new do
			for p in $network 

				if $filter =~ p and check_for_doubles(p.ip_src) == 0 and check_for_doubles(p.ip_dst) == 0

					netmask = IPAddr.new("255.255.255.0")
					netaddr = IPAddr.new(get_my_ip) & netmask
					broadaddr = netaddr | ~netmask

					ip = IPAddr.new(p.ip_src.to_s)

					if (ip & netmask) == netaddr and ip != broadaddr
						$hosts << { :ip_address => ip, :mac => "" }
						puts "Found new host #{ip}"
					end

					ip = IPAddr.new(p.ip_dst.to_s)

					if (ip & netmask) == netaddr and ip != broadaddr
						$hosts << { :ip_address => ip, :mac => "" }
						puts "Found new host #{ip}"
					end
				end
			end
		end
		string = gets
		if string == "\n"
			return
		end
	end

	def ui
		print "anne> "
		cmd_string = readline 

		cmd_args = []
		i = 0
		cmd_string.scan(/\w+/).each { |word| cmd_args[i] = word; i+=1 }
		if cmd_args[0] == "help"
			help(cmd_args[1]) { puts "List of commands:"; @@cmds.each { |cmd| print "#{cmd[:name]} " } }
			puts "\n"
		elsif cmd_args[0] == "scan"
			scan_handler(cmd_args[1]) do
				puts "List of things I can scan for:"
				@@scans.each { |scan| puts scan[:name] } 
			end
		elsif cmd_args[0] == "listen"
			listen_handler(cmd_args[1]) do
			puts "List of things I can listen for:"
			@@listens.each { |listen| puts listen[:name] } 
			end
		elsif cmd_args[0] == "quit"
			quit()
		elsif cmd_args[0] == "info"
			info()
		elsif cmd_args[0] == "hosts"
			put_host_list()
		end
	end
end

anne = Anne.new

anne.banner
loop do
	anne.ui
end
