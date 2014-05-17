package require nacl
puts "Key: [hexdump [set k [randombytes 32]]]"
set m [secretbox $k "Hello!"]
set nonce [lindex $m 0]
set msg [lindex $m 1]
puts "Nonce: [hexdump $nonce]"
puts "Message: [hexdump $msg]"
set dec [secretbox_open $k $nonce $msg]
puts "Data: $dec"
