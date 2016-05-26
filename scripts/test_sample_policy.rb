# Internal use only right now, sanity check code by hand
# cp sample_policy /var/lib/rightlink/login_policy; apt-get install -y ruby1.9.1-dev; gem install etcutils; ruby test_sample_policy.rb
# Temporary until c based unit tests written
require 'etc'
require 'pp'

puts "getpwnam rightscale_user_100:"
pp Etc.getpwnam("rightscale_user_100") rescue nil
puts ""; puts "";

puts "getpwnam rightscale_user_41000:"
pp Etc.getpwnam("rightscale_user_41000")
puts ""; puts "";

puts "getpwnam peter:"
pp Etc.getpwnam("peter")
puts ""; puts "";

puts "getpwuid 51000:"
pp Etc.getpwuid(51000)
puts ""; puts "";

if `whoami`.chomp == "root"
	require 'etcutils'
	puts "getspnam rightscale_user_100:"
	pp EtcUtils.getspnam("rightscale_user_100") rescue nil
	puts ""; puts "";

	puts "getspnam rightscale_user_41000:"
	pp EtcUtils.getspnam("rightscale_user_41000")
	puts ""; puts "";

	puts "getspnam peter:"
	pp EtcUtils.getspnam("peter")
	puts ""; puts "";

	# not in etcutils
	#puts "getspuid 51000:"
	#pp EtcUtils.getspuid(51000)
	#puts ""; puts "";
end

puts "getgrgid 510000:"
pp Etc.getgrgid(51000)
puts ""; puts "";

puts "getgrnam peter:"
pp Etc.getgrnam('peter')
puts ""; puts "";

puts "getgrnam rightscale_no_exist:";
pp Etc.getgrnam("rightscale_no_exist") rescue nil
puts ""; puts "";

puts "getgrnam rightscale:"
pp Etc.getgrnam("rightscale")
puts ""; puts "";

puts "getgrnam rightscale_sudo:"
pp Etc.getgrnam("rightscale_sudo")
puts ""; puts "";

puts "getgrgid 10001:"
pp Etc.getgrgid(10001)
puts ""; puts "";


puts "pwent loop:"
Etc.setpwent
Etc.setpwent
while(f = Etc.getpwent) 
  puts f.name
end
Etc.getpwent
Etc.endpwent
Etc.endpwent
puts ""; puts "";

puts "grent loop:"
Etc.setgrent
Etc.setgrent
while(f = Etc.getgrent) 
  puts f.name
end
Etc.getgrent
Etc.endgrent
Etc.endgrent
puts ""; puts "";

if `whoami`.chomp == "root"
	puts "spent loop:"
	EtcUtils.setspent
	EtcUtils.setspent
	while(f = EtcUtils.getspent) 
	  puts f.name
	end
	EtcUtils.getspent
	EtcUtils.endspent
	EtcUtils.endspent
	puts ""; puts "";
end
