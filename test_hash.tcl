package require nacl

proc test_hash {in out} {
    set h [hash -hex $in]
    if { $h == $out } {
        puts "hash: OK"
    } else {
        puts "hash: FAILED"
    }
}

test_hash "testing\n" 24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28

