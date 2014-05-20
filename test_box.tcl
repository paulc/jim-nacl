
package require nacl

set sender [ box_keypair ]
set sender_sk [lindex $sender 0]
set sender_pk [lindex $sender 1]

set recipient [ box_keypair ]
set recipient_sk [lindex $sender 0]
set recipient_pk [lindex $sender 1]

set data [ randombytes 1000 ]

set msg [ box $recipient_pk $sender_sk $data ]

puts [ hexdump $msg ]

if { [ box_open $sender_pk $recipient_sk {*}$msg ] == $data } {
    puts OK
} else {
    puts FAILED
}

