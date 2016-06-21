#!/usr/bin/env ruby
# this is myproc_control.rb
#require 'rubygems'
require 'daemons'

#pwd  = File.dirname(File.expand_path(__FILE__))
#file = pwd + '/../lib/background_service.rb'

Daemons.run_proc(
  'sfs', # name of daemon
#  :dir_mode => :normal
#  :dir => File.join(pwd, 'tmp/pids'), # directory where pid file will be stored
#  :backtrace => true,
#  :monitor => true,
  :log_output => true
) do
  exec "su - root -c /home/cjlapao/sfs/sfs_automatic.rb"
end
