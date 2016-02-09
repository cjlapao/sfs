#!/usr/bin/ruby
# Secure firewall analyser
# Will check for the log created by the secure file and add
# iptables rules to block the attempts to login
#
#author: Carlos Lapao
#Ver: 0.3.5
#rev: 1
#all rights reserved

# TODO: Implementing cli and colorize better the output of the system

$failcount = 0
$whitelist
$blacklist
$inprogress = []
$logfile = []
$_custom_path
$_path
$_nattempts
$_smtp
$_smtpuser
$_smtppasswd
$_email

# Checking if we have all the software necessary to run the script and will abort
# in case there's anything missing
def check_requisites
	begin
		puts "Checking if dig is installed"
		IO.popen("dig"){|_io| _io.close}
	rescue	StandardError
		puts "\e[0;31mNo dig installed, please install it before using this script\e[0m"
		abort
	end
	begin
		puts "Checking if dig is installed"
		IO.popen("mailx >/dev/null 2>&1"){|_io| _io.close}
	rescue	StandardError
		puts "\e[0;31mNo mailx installed, please install it before using this script\e[0m"
		abort
	end
end

class Open_log
	@@file = ""
	@@log = ""
	@@ruser = ""
	@@rhost = ""
	def initialize(filepath, filename)
		@filename = filename
		@filepath = filepath
		@@file = @filepath+"/"+@filename
	end
	# Checking if the selected file exists and trying to open it
	def check_file()
		if File.exist?(@@file)
			@@log = File.open(@@file,"rb")
			return true
		else
			@@log = ''
			return false
		end
	end
	# printing the file
	def print_path
		puts @@file.red
	end
	def header
		puts "\e[0;32mwhitelist ip's loaded into memory (#{$whitelist.size} records)...\e[0m"
		puts "\e[0;32mblacklist ip's loaded into memory (#{$blacklist.size} records)...\e[0m"
		puts "\e[0;32mAnalising...\e0m"
	end
	def analise
		if check_file == true
			t = Thread.new do
				puts "\e[0;32mFile exists, starting to analise... press enter to stop\e[0m"
				@@log.seek(0,IO::SEEK_END)
				_index=0
				while true
					select([@@log])
					_line = @@log.gets
					vectors(_line, _index) if _line.nil?  == false
					sleep(0.5)
				end
			end
			gets
			t.kill
		else
			puts "\e[0;31mFile #{@@file} does not exists, please check your conf file\e[0m"
		end
	end
	# checking if the ip is on a whitelist
	def check_whitelist(_ip)
		_found = false
		$whitelist.each{|_line|
		if !_line.include?('#')
			_line = _line[0.._line.length-2]
			_ip = _ip[0.._ip.length]
			if _line == _ip
				_found = true
			end
		end}
		if _found == true
			return true
		else
			return false
		end
	end
	#checking if the ip is on a blacklist
	def check_blacklist(_ip)
		# TODO: Implementing count of attempts and when should it be blocked by the
		# system
		_found = false
		$blacklist.each{|_line|
		if !_line.include?('#')
			_line = _line.chomp
			_ip = _ip.chomp
			if _line == _ip
				_found = true
			end
		end}
		if _found == true
			return true
		else
			return false
		end
	end
	def vectors(_line, _index)
		_trigger = true
		_date = _line[0..6]
		_time = _line[7..15]
		if _line.include?("sshd[") == true
			_id = _line[_line.index("sshd[")+5.._line.length]
			_id = _id[0.._id.index("]")-1]
		else
			_id ="0000"
		end
		_message = _line[_line.index(":")+2.._line.length]
		if _line.include?('pam_unix(sshd:auth): authentication failure;')
			if $inprogress.include?(_id) == false
				add_id(_id)
				_msg = "[#{_id}] Found 'authentication failure' entry, keeping an eye for abuse"
				puts "\e[0;33m#{_date} #{_time} #{_msg}\e[0m"
				addlog(_msg)
				$failcount = $failcount+1
				_trigger = true
			end
		elsif _line.include?('reverse mapping checking')
			if $inprogress.include?(_id) == false
				add_id(_id)
				_msg = "[#{_id}] Found 'reverse mapping checking' entry, keeping an eye for abuse"
				puts "\e[0;33m#{_date} #{_time} #{_msg}\e[0m"
				addlog(_msg)
				$failcount = $failcount+1
				_trigger = true
			end
		elsif _line.include?('Accepted password for')
			@@ruser = _line[_line.index(" for ")+5.._line.length]
			@@ruser = @@ruser[0..@@ruser.index(" ")-1]
			@@rhost = _line[_line.index("from ")+5.._line.length]
			@@rhost = @@rhost[0..@@rhost.index(" ")]
			if $inprogress.include?(_id) == false
				add_id(_id)
				_msg = "[#{_id}] Found 'Accepted Password' entry for #{@@ruser}#{@@rhost}, recording it and waiting for session to start"
				puts "\e[0;34m#{_date} #{_time} #{_msg}\e[0m"
				addlog(_msg)
				_trigger = false
			end
		elsif _line.include?('pam_unix(sshd:session)')
			if $inprogress.include?(_id) == true
				_msg = "[#{_id}] Found 'Session Sart' entry for #{@@ruser}@#{@@rhost}, reporting it to administrator"
				puts "\e[0;34m#{_date} #{_time} #{_msg}\e[0m"
				addlog(_msg)
				$inprogress.delete(_id)
				sendmail(1,@@rhost)
				_trigger = false
			end
		end
		if _trigger == true
			vector_trigger(_id,_message)
		end
	end
	# Checking for the line with the details of the abuser so we can release the countermeasures
	# we will need dig to be installed as we need to query the PTR tables to get an
	# ip rather than the rDNS that sometimes shows up on the log
	def vector_trigger(_id,_message)
		if $inprogress.include?(_id)
			if _message.include?("rhost=")
				_rhost = _message[_message.index("rhost")+6.._message.length]
				_rhost = _rhost[0.._rhost.index(" ")-1]
				#checking the real ip with dig and using it instead;
				_temp = ""
				_isDig = true
				begin
					_temp = IO.popen("dig #{_rhost} +short")
				rescue StandardError
					puts "\e[0;31mNo dig installed to lookup remote host IP\t\t\t\t[ERROR]\e[0m"
					isDig = false
					abort
				end
				if _isDig == true
					_temp.each{|line| _rhost= line.chomp}
				end
				if check_whitelist(_rhost) == false
					puts "\e[0;31m#{Time.now} Remote host '#{_rhost}' not on whitelist, reporting abuse and releasing countermeasures.\e[0m"
					if check_blacklist(_rhost) == false
							$blacklist[$blacklist.size] = _rhost
							f= File.open("blacklist.conf","a")
							f.write("#{_rhost}\n")
							f.close
					end
					addlog("[#{_id}] Remote host '#{_rhost}' not on whitelist, reporting abuse and releasing countermeasures.")#					countermeasures(_rhost)
					countermeasures(_rhost)
				else
					puts "\e[0;32m#{Time.now} Remote host '#{_rhost}' on whitelist, reporting the error to admin\e[0m"
					addlog("[#{_id}] Remote host '#{_rhost}' on whitelist, reporting the error to admin")
				end
				$inprogress.delete(_id)
			end
		end
	end
	# Add the job id being analised on a array for later use
	def add_id(_id)
		if $inprogress.size > 0
			if !$inprogress.include?(_id)
				$inprogress[$inprogress.size] = _id
			end
		else
			$inprogress[0] = _id
		end
	end
	def addlog(_message)
		if $logfile.size > 0
			$logfile[$logfile.size] = "#{Time.now} : #{_message}"
		else
			$logfile[0] = "#{Time.now} : #{_message}"
		end
	end
	def savelog
		if File.exist?("secure_firewall.log") == true
			f = File.open("secure_firewall.log","a")
			$logfile.each{|_line| f.write("#{_line}\n")}
			f.close
		else
			f = File.open("secure_firewall.log","w")
			$logfile.each{|_line| f.write("#{_line}\n")}
			f.close
		end
	end
	# Activating countermeasures on the abusing ip
	def countermeasures(_ip)
		_out = ""
		IO.popen("iptables -nL INPUT | grep #{_ip}"){|_io|
			_out = _io.readlines
			_io.close
		}
		if _out.size == 0
			puts "\r\e[0;37miptables rule not found applying \t\t\t\t\e[0;32m[DONE]\e[0m"
			IO.popen("iptables -I INPUT -s #{_ip} -j DROP"){|_io| _io.close}
			IO.popen("iptables -I INPUT -s #{_ip} -j LOG --log-prefix '[Blocked IP]'"){|_io| _io.close}
			if File.exist?("#{$_custom_path}/custom")
				_file = File.open("#{$_custom_path}/custom","a")
			else
				_file =  File.open("#{$_custom_path}/custom","w")
			end
			_file.write("iptables -I INPUT -s #{_ip} -j DROP\n")
			_file.write("iptables -I INPUT -s #{_ip} -j LOG --log-prefix '[Blocked IP]'\n")
			_file.close
			puts "\r\e[0;37miptables logged and saved \t\t\t\t\t\e[0;32m[DONE]\e[0m"
			sendmail(0,_ip)
		else
			puts "\r\e[0;33mRule already exists. \e[0;32m[DONE]\e[0m"
		end
	end
	def sendmail(_index,_ip)
		begin
			if _index == 0
				_subject = "as breached the rules and has been banned"
				_body = "Alara systems\n\nPlease note that the IP[#{_ip}] as been blocked "+
					"from accessing the alara network, if this is a mistake Please review the "+
					"system settings.\n\n\nGenerated by SFS on Alara Wholefoods @#{Time.now}"+
					"\nCreated by ittech24.co.uk all rights reserved"
			elsif _index == 1
				_subject = "logged in to the system, please check if it is authorised"
				_body = "Alara systems\n\nPlease note that the IP[#{_ip}] Logged in "+
					"on the alara network, Please check if this is an authorised connection"+
					"\n\n\nGenerated by SFS on Alara Wholefoods @#{Time.now}"+
					"\nCreated by ittech24.co.uk all rights reserved"
			elsif _index == 2
				_subject = "SFS System started"
				_body =  "SFS automatic system started on the server"+
					"\n\n\nGenerated by SFS on Alara Wholefoods @#{Time.now}"+
					"\nCreated by ittech24.co.uk all rights reserved"
			end

			IO.popen("echo '#{_body}' |"+
				"mailx -r 'it@alara.co.uk' -s '[SFS] IP #{_ip} #{_subject}' "+
				"-S smtp='#{$_smtp}:25' "+
				"-S smtp-auth=login "+
				"-S smtp-auth-user='#{$_smtpuser}' "+
				"-S smtp-auth-password='#{$_smtppasswd}' "+
				"#{$_email}"){|_io| _io.close}
		rescue StandardError => error
			puts "\e[0;31mError sending email to administrator, please review the conf file\t\t\t\t[ERROR]\e[0m"
			puts "\e[0;31m'#{error}'\e[0m"
		else
			puts "\e[0;37mSend email... \t\t\t\t\t\t\t\e[0;32m[DONE]\e[0m"
		end
	end
end

system "clear"
#check_requisites

print 'Choose file to analyse: '
_filename = gets.chomp

if _filename ==''
	_filename = 'secure'
end
# Loading config file and getting the global settings
if File.exist?("settings.conf")
	_settings = File.open("settings.conf","rb")
	_lines = _settings.readlines
	_lines.each{|_line|
		if _line.include?('file_path=')
			$_path = _line[_line.index('=')+1.._line.length-2]
		end
		if _line.include?('custom_path=')
			$_custom_path = _line[_line.index('=')+1.._line.length-2]
		end
		if _line.include?('nattempts')
			$_nattempts = _line[_line.index('='+1.._line.length-2)]
		end
		if _line.include?('smtp=')
			$_smtp = _line[_line.index('=')+1.._line.length-2]
		end
		if _line.include?('user=')
			$_smtpuser = _line[_line.index('=')+1.._line.length-2]
		end
		if _line.include?('passwd=')
			$_smtppasswd = _line[_line.index('=')+1.._line.length-2]
			_out = []
			IO.popen("echo ""#{$_smtppasswd}"" | base64 --decode"){|_io| _out = _io.readlines}
			$_smtppasswd = _out[0].chomp
		end
		if _line.include?('email=')
			$_email = _line[_line.index('=')+1.._line.length-2]
		end
		}
	_settings.close
end
# Loading the whitelist ip addresses to compare
if File.exist?("whitelist.conf")
	_whitelist = File.open("whitelist.conf","rb")
	$whitelist = _whitelist.readlines
	puts "\e[0;32mwhitelist ip's loaded into memory (#{$whitelist.size} records)...\e[0m"
	_whitelist.close
else
	_whitelist = File.open("whitelist.conf","w")
	_whitelist.write("#list of ip's that are whitelisted and will not be checked uppon")
	_whitelist.close
end
# Loading the blacklist ip addresses to compare
if File.exist?("blacklist.conf")
	_blacklist = File.open("blacklist.conf","rb")
	$blacklist = _blacklist.readlines
	puts "\e[0;32mblacklist ip's loaded into memory (#{$blacklist.size} records)...\e[0m"
	_blacklist.close
else
		_blacklist = File.open("blacklist.conf","w")
		_blacklist.write("#list of ip's that are blacklisted and will not be checked uppon")
		_blacklist.close
end


l = Open_log.new($_path,_filename)

l.sendmail(2,"Starting")

l.analise
puts "finished analysing and found #{$failcount} incidents"
l.savelog
