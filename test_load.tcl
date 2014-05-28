
package require nacl

proc test_auth {l} {
    set k [randombytes 32]
    set m [randombytes $l]
    set a [ auth $k $m ]
    if { [ catch {auth_verify $k $a $m} msg opts ] } {
        puts "  auth-$l: FAILED"
    } else {
        puts "  auth-$l: OK"
    }
}

proc test_stream {l} {
    set k [randombytes 32]
    set m [randombytes $l]
    lassign [stream $k $m] n c
    lassign [stream -nonce $n $k $c] _ d 
    if { $m == $d } {
        puts "  stream-$l: OK"
    } else {
        puts "  stream-$l: FAILED"
    }
}

proc test_secretbox {l} {
    set k [randombytes 32]
    set m [randombytes $l]
    lassign [secretbox $k $m] n c
    set d [secretbox_open $k $n $c ]
    if { $m == $d } {
        puts "  secretbox-$l: OK"
    } else {
        puts "  secretbox-$l: FAILED"
    }
}

proc test_box {l} {
    lassign [box_keypair] sender_pk sender_sk
    lassign [box_keypair] recipient_pk recipient_sk
    set data [ randombytes $l ]
    set c [ box $recipient_pk $sender_sk $data ]
    if { [ box_open $sender_pk $recipient_sk {*}$c ] == $data } {
        puts "  box-$l: OK"
    } else {
        puts "  box-$l: FAILED"
    }
}

proc test_sign {l} {
    lassign [sign_keypair] pk sk
    set m [randombytes $l]
    set sm [sign $sk $m]
    if { [sign_open $pk $sm] == $m } {
        puts "  sign-$l: OK"
    } else {
        puts "  sign-$l: FAILED"
    }
}

for {set i 0} {$i < 1000} {incr i} {
    puts "=== Count: $i"
    foreach t {test_auth test_stream test_box test_secretbox test_sign} {
        foreach l {0 10 100 1000 10000 100000 1000000} {
            $t $l
        }
    }
}

