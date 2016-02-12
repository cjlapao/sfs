

@domain
@username
@password

IO.popen('ldapsearch -LLL -H ldap://alarasvr.factory.alara.co.uk -x -D "factory\cjlapao" -w "!512Cf61b" -b "dc=factory,dc=alara,dc=co,dc=uk" "objectClass=computer" name
') {|s1|
  s1.each{|line|
    if line.include?('name:')
      puts line
    end
  }
}
