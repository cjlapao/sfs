require 'rubygems'
require 'net/ssh'

@hostname = "192.168.1.22"
@username = "root"
@password = "A1ara45678"
@cmd = "reboot"
@msgtitle = '"Software Deployment"'
@msgbody = '"Starting to deploy software on the machine"'


  Net::SSH.start(@hostname, @username, :password => @password) do |ssh|
    ssh.exec("notify-send -t 10 [#{@msgtitle}] #{@msgbody}")
    ssh.exec("dnf -y install thunderbird") do |dc, stream, data|
      puts "#{data}"
  end
end
