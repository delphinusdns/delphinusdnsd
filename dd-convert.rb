#!/usr/local/bin/ruby
#
# $Id: dd-convert.rb,v 1.2 2015/11/07 19:00:38 pjp Exp $
#
# Copyright (c) 2015 Peter J. Philipp
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#
# nvi, ts=2
#
# This utility to delphinusdnsd takes a delphinusdnsd zonefile and converts
# it to BIND style zonefile, It then does dnssec-signzone from the BIND 
# utilities and with help of the dns-zone gem (version 0.2.0+) from Luke 
# Antins converts the signed zone back to delphinusdnsd zonefile format.  
# One day perhaps I'll write my own zonefile signer, but not today.
#

require 'fileutils'
require 'optparse'
require 'openssl'
require 'pp'
require 'tempfile'

require 'etc'
require 'dns/zone'

#
#
# Class ParseArguments, parses the commandline arguments, returns a hash
#
#

class ParseArguments < Hash
	def initialize(args)
		super()
		self[:zonename] = "centroid.eu."
		self[:numbits] = 1024 
		self[:KSK] = 0
		self[:ZSK] = 0
		self[:algorithm] = "rsasha256"
		self[:kskname] = ""
		self[:zskname] = ""
		self[:salt] = ""
		self[:ttl] = 3600
		self[:iterations] = 10

		opts = OptionParser.new do |opts|
			opts.banner = "Usage: #$0 [options]"

			opts.on('-a', '--algorithm ALG', 'the signing algorithm, default is rsasha256') do |alg|
				if alg != "rsasha1"
					puts "illegal algorithm!"
					exit 1
				end
			end

			opts.on('-B', '--bits NUMBITS', 'the amount of bits to sign this keypair') do |bits|
				if bits > 512 && bits < 4096 then
					self[:numbits] = bits
				else
					puts "illegal bitsize for keys!"
					exit 1
				end
			end

			opts.on('-I', '--iterations num', 'iterations of NSEC3 hash') do |filename|
				self[:iterations] = filename
			end

			opts.on('-i', '--input INPUTFILE', 'the delphinusdns zonefile') do |filename|
				self[:input] = filename
				self[:bindfile] = ""
				if !File.exist?(filename) then
					puts "no such inputfile"
					exit 1
				end
			end

			opts.on('-K', '--KSK', 'create KSK keys') do |ksk|
				self[:KSK] = 1
			end

			opts.on('-k', '--kskname KEY', 'use specific KSK key') do |kskname|
				self[:kskname] = kskname || ''
			end

			opts.on('-n', '--name ZONENAME', 'the zonename of the zone to work on') do |filename|
				self[:zonename] = filename || ''
				if self[:zonename][-1] == '.' then
					puts 'trailing dot not allowed here'
					exit 1
				end
			end

			opts.on('-o', '--output OUTPUTFILE', 'the signed output zonefile') do |filename|
				self[:output] = filename
				if !File.exist?(filename) then
					puts "no such outputfile"
					exit 1
				end
			end

			opts.on('-s', '--salt SALT', 'the salt for the NSEC3') do |filename|
				self[:salt] = filename || ''
			end

			opts.on('-t', '--ttl TTL', 'the TTL for the keys') do |filename|
				self[:ttl] = filename
			end

			opts.on('-Z', '--ZSK', 'create ZSK keys') do |zsk|
				self[:ZSK] = 1
			end

			opts.on('-z', '--zskname KEY', 'use specific ZSK key') do |zskname|
				self[:zskname] = zskname || ''
			end

			opts.on_tail('-h', '--help', 'display this help and exit') do 
				puts opts
				exit 0
			end
		end

		opts.parse!(args)
	end
end

#
#
# Class InputFile parses the input config file, returns an Array
#
#

class MyTranslation < Array
	#
	# @@name2rr is a hash that translates a given key name to a number
	#
	@@name2rr = { 	"a" 	=> 	1,
			"A" 	=> 	1,
			"ns" 	=>	2,
			"NS" 	=>	2,
			"delegate" =>	2,
			"DELEGATE" =>	2,
			"hint"	=>	2,
			"HINT"	=>	2,
			"cname" =>	5,
			"CNAME" =>	5,
			"soa"	=>	0,		# this is a hack
			"SOA"	=>	0,		# it really is 6
			"ptr"	=>	12,
			"PTR"	=>	12,
			"mx"	=>	15,
			"MX"	=>	15,
			"txt"	=>	16,
			"TXT"	=>	16,
			"aaaa"  =>	28,
			"AAAA"  =>	28,
			"srv"	=>	33,
			"SRV"	=>	33,
			"naptr" =>	35,
			"NAPTR" =>	35,
			"opt"	=>	41,
			"OPT"	=>	41,
			"ds"	=>	43,
			"DS"	=>	43,
			"sshfp"	=>	44,
			"SSHFP"	=>	44,
			"rrsig" =>	46,
			"RRSIG" =>	46,
			"nsec"	=>	47,
			"NSEC"	=>	47,
			"dnskey" =>	48,
			"DNSKEY" =>	48,
			"nsec3" =>	50,
			"NSEC3" =>	50,
			"nsec3param" => 51,
			"NSEC3PARAM" => 51,
			"spf"	=>	99,
			"SPF"	=>	99,
			"tsig"	=>	250,
			"TSIG"	=>	250,
			"ixfr"	=>	251,
			"IXFR"	=>	251,
			"axfr"	=>	252,
			"AXFR"	=>	252,
			"any"	=>	255,
			"ANY"	=>	255
		}

	#
	# @@rr2name is a hash that translates a name to a given rrtype string
	#
	@@rr2name = {
			1 	=> 	"a",
			2	=>	"ns",
			5	=>	"cname",
			6	=>	"soa",		
			12	=>	"ptr",
			15	=>	"mx",
			16	=>	"txt",
			28	=>	"aaaa",
			33	=>	"srv",
			35	=>	"naptr",
			41	=>	"opt",
			43	=>	"ds",
			44	=>	"sshfp",
			46	=>	"rrsig",
			47	=>	"nsec",
			48	=>	"dnskey",
			50	=>	"nsec3",
			51	=>	"nsec3param",
			99	=>	"spf",
			250	=>	"tsig",
			251	=>	"ixfr",
			252	=>	"axfr",
			255	=>	"any",
		}


end

class ConvertD2B < MyTranslation
	def initialize(filename)
		super()
		m = []
		ttl = 0

		linenum = 0
		filename.each() do |line|
			if line != nil then
				m = line.split(',')
				if m[1] == nil then
					next
				elsif m[1].downcase == "soa" then
					self[linenum] = '$TTL ' + m[2]
					linenum += 1
					ttl = m[2].to_i
					if m[0][-1] == "." then
						self[linenum] = '$ORIGIN ' + m[0]
						origin = m[0]
					else
						self[linenum] = '$ORIGIN ' + m[0] + '.'	
						origin = m[0] + '.'
					end
					linenum += 1
					self[linenum] = origin + " IN SOA " + m[3] 
					self[linenum] += " " + m[4] + " ( "
					self[linenum] += m[5] + " " + m[6]
					self[linenum] += " " + m[7] + " "
					self[linenum] += m[8] + " " + m[9]
					self[linenum] += " )"
					linenum += 1
				elsif m[1].downcase == "ns" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN NS " + m[3]

					linenum += 1
				elsif m[1].downcase == "a" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN A " + m[3]

					linenum += 1
				elsif m[1].downcase == "aaaa" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN AAAA " + m[3]

					linenum += 1
				elsif m[1].downcase == "cname" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN CNAME " + m[3]

					linenum += 1
				elsif m[1].downcase == "ptr" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN PTR " + m[3]

					linenum += 1
				elsif m[1].downcase == "txt" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN TXT " + m[3]

					linenum += 1
				elsif m[1].downcase == "spf" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN SPF " + m[3]

					linenum += 1
				elsif m[1].downcase == "mx" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN MX " + m[3] 
					self[linenum] += " " + m[4]

					linenum += 1
				elsif m[1].downcase == "srv" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN SRV " + m[3] 
					self[linenum] += " " + m[4] + " "
					self[linenum] += m[5] + " " + m[6]

					linenum += 1
				elsif m[1].downcase == "sshfp" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN SSHFP " + m[3] 
					self[linenum] += " " + m[4] + " (" 
					m[5][0] = ' ';
					m[5][-1] = ' ';
					self[linenum] += m[5] + ")"

					linenum += 1
				elsif m[1].downcase == "naptr" then
					if m[0][-1] == "." then
						self[linenum] = m[0]
					else
						self[linenum] = m[0] + '.'	
					end
					if m[2].to_i != ttl then
						self[linenum] += " " + m[2]
					end
					self[linenum] += " IN NAPTR (" + m[3] 
					self[linenum] += " " + m[4] + " " 
				 	self[linenum] += m[5] + " " + m[6]	
					self[linenum] += " " + m[7] + " " 
				 	self[linenum] += m[8] + " )"

					linenum += 1
				end
					
			end
		end

	end
end

class InputFile < MyTranslation
	def initialize(filename, zonename)
		super()
		inputfile = []
		zonefile = []
		m = []
		savezonename = zonename
		linecount = 0

		if filename == nil
			usage
		end
		

		f = File.open(filename, "r") 
			while !f.eof do 
				inputfile << f.readline
			end
		f.close

		zone = false
		zonename = '"' + zonename + '"'
		inputfile.each() do |line| 
			m = line.split
			if m[0] == "zone" && m[1] == zonename then
				zone = true
			end
			if zone == true then
				zonefile << line
				if line =~ /^.*}/ then
					zone = false
					break
				end
			end
		end

		delete inputfile
		zonefile.sort!

		# first pass, sort by RRSET

		#puts "zone \"" + savezonename + "\" {"
		# pjp 20151012
		#self[linecount] = "zone \"" + savezonename + "\" {"
		#linecount += 1

		count = 0
		lastname = savezonename
		# sort the records after rrset
		zonefile.each() do |line|
			count += 1
			m = self.lookup_record(zonefile, count)
			if m == nil then
				next
			end
		
			domainname = m[0].strip
			if domainname.downcase != lastname then
				n = self.sort_domaintypes(zonefile, count, lastname)
				lastrr = n[0]
				n.each() do |x|
					self[linecount] = x.join(",")
					linecount += 1
					#print "\t"
					#puts x.join(",")
					lastrr = x
				end
			end

			lastname = domainname.downcase
		end

		#puts "}"
		# pjp 20151012
		#self[linecount] = "}"
	end

	def lookup_record(zonefile, number)
		line = zonefile[number]	

		if line =~ /zone/ || line =~ /^.*;/ then
			return nil
		end
		
		if line == nil then
			return nil
		end

		m = line.split(',')
		
		return m
	end

	def sort_domaintypes(zonefile, number, domainname)  
		replace = []
		save = ""
		count = number 
		(number - 1).downto(0).each() do |line|
			count -= 1
			m = self.lookup_record(zonefile, line)
			if m == nil then
				next
			end
			if m[0].strip.downcase != domainname then
				break
			end
			m.each() do |x|
				x.strip!
				x.chomp!
			end
			replace << m
		end

		# pjp
		replace.sort_by! { |f| [ @@name2rr[f[1]] ]}
		return replace
	end
end


#
# Class MyCreateKSK - create a KSK and write it out
#
#

class MyCreateKeys < Hash
	#
	# taken from:
	# http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
	# may be updated
	# we only support 2 of these rsasha1 and rsasha256
	#
	@@alg2num = {
			"rsamd5"		=>	1,
			"dh"			=>	2,
			"dsa"			=>	3,
			"rsasha1"		=>	5,
			"dsa-nsec3-sha1"	=>	6,
			"rsasha1-nsec3-sha1"	=>	7,
			"rsasha256"		=>	8,
			"rsasha512"		=>	10,
			"ecc-gost"		=>	12,
			"ecdsap256sha256"	=>	13,
			"ecdsap384sha384"	=>	14
		}

	def initialize(type, algorithm, bits, zonename, ttl)
		self[:zskname] = ''
		self[:kskname] = ''
		systemid = [] 
		super()

		systemid = Etc.uname[:sysname]
		
		if type == 1 then
			createKSK(algorithm, bits, zonename, ttl, systemid)	
		else
			createZSK(algorithm, bits, zonename, ttl, systemid)
		end
	end

	def createKSK(algorithm, bits, zonename, ttl, systemid)
		if systemid == "OpenBSD" then
			keygen = "/usr/local/sbin/dnssec-keygen"
		elsif systemid == "FreeBSD" then
			keygen = "/usr/sbin/dnssec-keygen"
		end
		
		IO.popen(keygen + ' -3 -L ' + \
			ttl.to_s + ' -f KSK -a ' + algorithm + \
			' -b ' + bits.to_s + ' -n zone ' + \
			zonename, 'r+') do |pipe|

			self[:kskname] = pipe.read
		end

	end

	def createZSK(algorithm, bits, zonename, ttl, systemid)
		if systemid == "OpenBSD" then
			keygen = "/usr/local/sbin/dnssec-keygen"
		elsif systemid == "FreeBSD" then
			keygen = "/usr/sbin/dnssec-keygen"
		end
		
		IO.popen(keygen + ' -3 -L ' + \
			ttl.to_s + ' -a ' + algorithm + \
			' -b ' + bits.to_s + ' -n zone ' + \
			zonename, 'r+') do |pipe|

			self[:zskname] = pipe.read
		end
	end
end

#
# usage
#
def usage
	ParseArguments.new(Hash.new("--help"));
	exit 1
end


#
# start 
#

systemid = [] 
systemid = Etc.uname[:sysname]

arguments = ParseArguments.new(ARGV)

if arguments[:input] != "" then
	puts '################################################################'
	inputfile = InputFile.new(arguments[:input], arguments[:zonename])
	#puts inputfile
	bindfile = ConvertD2B.new(inputfile)
	out = Tempfile.new('master.' + arguments[:zonename]);
	bindfile.to_a.each() do |line|
		out.puts line
	end

	if arguments[:KSK] == 1 then
		arguments[:kskname] = MyCreateKeys.new(1 , arguments[:algorithm], arguments[:numbits], arguments[:zonename], arguments[:ttl])[:kskname]
		puts 'created KSK key ' + arguments[:kskname]
	end

	if arguments[:ZSK] == 1 then
		arguments[:zskname] = MyCreateKeys.new(2 , arguments[:algorithm], arguments[:numbits], arguments[:zonename], arguments[:ttl])[:zskname]
		puts 'created ZSK key ' + arguments[:zskname]
	end

	if arguments[:kskname] == '' then
		puts 'unknown KSK'
		exit 1
	end

	if arguments[:zskname] == '' then
		puts 'unknown ZSK'
		exit 1
	end
	
	open(arguments[:kskname].chomp + '.key') { |f| out.puts f.read }
	open(arguments[:zskname].chomp + '.key') { |f| out.puts f.read }

	out.rewind

	if systemid == "OpenBSD" then
		signzonepath = "/usr/local/sbin/dnssec-signzone"
	elsif systemid == "FreeBSD"
		signzonepath = "/usr/sbin/dnssec-signzone"
	end

	
	IO.popen(signzonepath + ' -O full -3 \'' + \
		arguments[:salt] + '\' -H ' + arguments[:iterations].to_s + \
		' -o ' + arguments[:zonename] + '. -t  -k ' + \
		arguments[:kskname].chomp + ' ' + out.path + ' ' + \
		arguments[:zskname].chomp , 'r+') do |pipe|

		puts pipe.read
	end

	signed = out.path + '.signed'
	out.close
		
	zone = DNS::Zone.load(open(signed))
	File.delete signed

	if arguments[:output] != '' then
		output = open(arguments[:zonename] + '.signed', 'w+');
		output.puts '; this file is automatically generated, do NOT edit'
		output.puts '; it was generated by dd-convert.rb'
		output.puts 'zone "' + arguments[:zonename] + '" {'
	else
		puts 'You didn\'t specify an output file...exit.'
		exit 0
	end

	zone.records.each() do |record|
		field = record.to_s.split(":");
		
		type = field[6]
		if type == "SOA" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',soa,' +  \
				dnsfield[1] + ',' + \
				record.nameserver + ',' + \
				record.email.to_s + ',' + \
				record.serial.to_s + ',' + \
				record.refresh_ttl.to_s + ',' + \
				record.retry_ttl.to_s + ',' + \
				record.expiry_ttl.to_s + ',' + \
				record.minimum_ttl.to_s
		elsif type == "A" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',a,' + \
				dnsfield[1] + ',' + record.address
		elsif type == "AAAA" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',aaaa,' + \
				dnsfield[1] + ',' + record.address
		elsif type == "TXT" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',txt,' + \
				dnsfield[1] + ',' + record.text
		elsif type == "SPF" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',spf,' + \
				dnsfield[1] + ',"' + record.text + '"'
		elsif type == "RRSIG" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',rrsig,' + \
				dnsfield[1] + ',' + \
				record.type_covered + ',' + \
				record.algorithm.to_s + ',' + \
				record.labels.to_s + ',' + \
				record.original_ttl.to_s + ',' + \
				record.signature_expiration.to_s + ',' + \
				record.signature_inception.to_s + ',' + \
				record.key_tag.to_s + ',' + \
				record.signer.to_s.gsub(/ /, "") + ',"' + \
				record.signature.to_s.gsub(/ /, "") + '"'
		elsif type == "NSEC3PARAM" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',nsec3param,' + \
				dnsfield[1] + ',' + \
				record.algorithm.to_s + ',' + \
				record.flags.to_s + ',' + \
				record.iterations.to_s + ',"' + \
				record.salt.to_s + '"'
		elsif type == "NSEC3" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',nsec3,' + \
				dnsfield[1] + ',' + \
				record.algorithm.to_s + ',' + \
				record.flags.to_s + ',' + \
				record.iterations.to_s + ',"' + \
				record.salt.to_s + '","' + \
				record.next_hashed_owner_name.to_s + '","' + \
				record.rrset_types.to_s + '"'
		elsif type == "NSEC" then
			#dnsfield = record.general_prefix
			#output.puts '  ' + dnsfield[0] + ',nsec,completeme'
		elsif type == "DNSKEY" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',dnskey,' + \
				dnsfield[1] + ',' + \
				record.flags.to_s + ',' + \
				record.protocol.to_s + ',' + \
				record.algorithm.to_s + ',"' + \
				record.key.to_s.gsub(/ /, "") + '"' 	
		elsif type == "DS" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',ds,' + \
				dnsfield[1] + ',' + \
				record.key_tag.to_s + ',' + \
				record.algorithm.to_s + ',' + \
				record.digest_type.to_s + ',"' + \
				record.digest.to_s.gsub(/ /, "") + '"'
		elsif type == "MX" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',mx,' + \
				dnsfield[1] + ',' + \
				record.priority.to_s + ',' + \
				record.exchange.to_s 
		elsif type == "NS" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',ns,' + \
				dnsfield[1] + ',' + \
				record.nameserver
		elsif type == "CNAME" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',cname,' + \
				dnsfield[1] + ',' + \
				record.domainname	
		elsif type == "PTR" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',ptr,' + \
				dnsfield[1] + ',' + \
				record.name
			
		elsif type == "NAPTR" then
# bogus , catch later!
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',naptr,' + \
				dnsfield[1] + ',' + \
				record.order.to_s + ',' + \
				record.pref.to_s + ',' + \
				record.flags + ',"' + \
				record.service + '","' + \
				record.regexp + '",' + \
				record.replacement
		elsif type == "SRV" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',srv,' + \
				dnsfield[1] + ',' + \
				record.priority.to_s + ',' + \
				record.weight.to_s + ',' + \
				record.port.to_s + ',' + \
				record.target.to_s 	
		elsif type == "SSHFP" then
			dnsfield = record.general_prefix
			output.puts '  ' + dnsfield[0] + ',sshfp,' + \
				dnsfield[1] + ',' + \
				record.algorithm_number.to_s  + ',' + \
				record.fingerprint_type.to_s + ',"' + \
				record.fingerprint.to_s.gsub(/ /, "") + '"'

		end
	end

	output.puts '}'

	puts 'DS set is called dsset-' + arguments[:zonename] + '.'
	puts 'Signed Zone is called ' + arguments[:zonename] + '.signed, enjoy!'
	puts '################################################################'

	exit 0
end

if arguments[:bindfile] != "" then
	inputfile = BindInputFile.new(arguments[:bindfile], arguments[:zonename])
	puts inputfile
end

exit 0
