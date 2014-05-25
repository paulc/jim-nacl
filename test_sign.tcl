
package require nacl

proc err {s} {
    set i [rand [string length $s]]
    return [string replace $s $i [expr $i + 1] [randombytes 1]]
}

proc test_sign {t n} {
    lassign [sign_keypair] pk sk
    set m [randombytes $n]
    set sm [sign $sk $m]
    if { [sign_open $pk $sm] == $m } {
        puts "$t: OK"
    } else {
        puts "$t: FAILED"
    }
}

proc test_sign_err {t n} {
    lassign [sign_keypair] pk sk
    set m [randombytes $n]
    set sm [err [sign $sk $m]]
    if { [catch {sign_open $pk $sm} msg opts] &&
            $msg == "ERROR: Invalid signature"} {
        puts "$t: OK"
    } else {
        puts "$t: FAILED"
    }
}

test_sign "sign-rand-10" 10
test_sign "sign-rand-1000" 1000
test_sign "sign-rand-100000" 100000

test_sign_err "sign-rand-10-err" 10
test_sign_err "sign-rand-1000-err" 1000
test_sign_err "sign-rand-100000-err" 100000
