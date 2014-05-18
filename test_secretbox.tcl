package require nacl

proc shorten {s n} {
    if { [string length $s] < $n } {
        return $s
    } else {
        return "[string range $s 0 [expr {$n - 3}]]..."
    }
}

proc test_secretbox {t k m} {
    set c [secretbox $k $m]
    set d [secretbox_open $k {*}$c ]
    puts "Message:   [shorten [hexdump $m] 60]"
    puts "Nonce:     [shorten [hexdump [lindex $c 0]] 60]"
    puts "Secretbox: [shorten [hexdump [lindex $c 1]] 60]"
    if { $m == $d } {
        puts "$t: OK"
    } else {
        puts "$t: FAILED"
    }
}

puts "Key: [hexdump [set k [randombytes 32]]]"

test_secretbox "rand-10" $k [randombytes 10]
test_secretbox "rand-1000" $k [randombytes 1000]
test_secretbox "rand-100000" $k [randombytes 100000]

