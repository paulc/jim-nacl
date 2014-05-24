
package require nacl

proc err {s} {
    set i [rand [string length $s]]
    return [string replace $s $i [expr $i + 1] [randombytes 1]]
}

proc bytes {b} {
    return [ unhexdump [ string map { "0x" "" ","  "" " "  "" "\n" "" } $b ]]
}

# From NaCl testsuite

append k "Jefe" [string repeat \x00 28] 

set m "what do ya want for nothing?"

set a [ bytes {
,0x16,0x4b,0x7a,0x7b,0xfc,0xf8,0x19,0xe2
,0xe3,0x95,0xfb,0xe7,0x3b,0x56,0xe0,0xa3
,0x87,0xbd,0x64,0x22,0x2e,0x83,0x1f,0xd6
,0x10,0x27,0x0c,0xd7,0xea,0x25,0x05,0x54
} ]

if { [ auth $k $m ] == $a } {
    puts "auth: OK"
} else {
    puts "auth: FAILED"
}

if { [ catch {auth_verify $k [ auth $k $m ] $m} msg opts ] } {
    puts "auth_verify: FAILED"
} else {
    puts "auth_verify: OK"
}
