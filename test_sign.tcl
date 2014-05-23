
package require nacl

lassign [ sign_keypair ] pk sk

set sm [ sign $sk Hello ]

puts [ sign_open $pk $sm ]
