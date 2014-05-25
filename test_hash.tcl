package require nacl

proc test_hash {a in out} {
    set h [hash -hex -$a $in]
    if { $h == $out } {
        puts "hash ($a): OK"
    } else {
        puts "hash ($a): FAILED"
    }
}

test_hash sha256 "testing\n" 12a61f4e173fb3a11c05d6471f74728f76231b4a5fcd9667cef3af87a3ae4dc2

test_hash sha512 "testing\n" 24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28

