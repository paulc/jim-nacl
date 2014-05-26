
package require nacl

proc test_secretbox {t l} {
    set k [randombytes 32]
    set m [randombytes $l]
    lassign [secretbox $k $m] n c
    set d [secretbox_open $k $n $c ]
    if { $m == $d } {
        puts "$t: OK"
    } else {
        puts "$t: FAILED"
    }
}

proc test_box {t l} {
    lassign [box_keypair] sender_pk sender_sk
    lassign [box_keypair] recipient_pk recipient_sk
    set data [ randombytes $l ]
    set c [ box $recipient_pk $sender_sk $data ]
    if { [ box_open $sender_pk $recipient_sk {*}$c ] == $data } {
        puts "$t: OK"
    } else {
        puts "$t: FAILED"
    }
}

for {set i 0} {$i < 1000} {incr i} {
    puts "=== Count: $i"
    foreach l {0 10 100 1000 10000 100000 1000000 10000000} {
        test_box "box-$l" $l
        test_secretbox "secretbox-$l" $l
    }
}

