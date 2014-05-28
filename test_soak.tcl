
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
    lassign [ box $recipient_pk $sender_sk $data ] n c
    if { [ box_open $sender_pk $recipient_sk $n $c ] == $data } {
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

set count 10
set max 10000
set tests [list auth stream box secretbox sign]

set i 0

while {[string index [lindex $argv $i] 0] == "-"} {
    if {[lindex $argv $i] == "-count"} {
        incr i
        set count [lindex $argv $i]
    } elseif {[lindex $argv $i] == "-max"} {
        incr i
        set max [lindex $argv $i]
    } elseif {[lindex $argv $i] == "-tests"} {
        incr i
        set tests [split [lindex $argv $i] " ,|"]
    } else {
        puts "Usage: $argv0 \[-count <n>\] \[-max <n>\] \[-tests auth|stream|box|secretbox|sign\]"
        exit 1
    }
    incr i
}

if {[llength $argv] != $i} {
    puts "Usage: $argv0 \[-count <n>\] \[-max <n>\]"
    exit 1
}

set i 0
set range {0}
while {10**$i <= $max} {
    lappend range [expr 10**$i]
    incr i
}

for {set i 0} {$i < $count} {incr i} {
    puts "=== Count: [expr $i + 1]"
    foreach t $tests {
        foreach l $range {
            test_$t $l
        }
    }
}

