
#include <jim.h>
#include <string.h>

#include "tweetnacl.h"
#include "zbase32.h"

#define rc(x) printf("Ref Count <%s>: %d\n",#x,x->refCount);
#define hd(x) printf("%s: %s\n",#x,Jim_String(Jim_HexString(interp,(x))));

static Jim_Obj *Jim_EmptyString(Jim_Interp *interp, int length) {
    Jim_Obj *empty = Jim_NewObj(interp);
    empty->bytes = Jim_Alloc(length + 1);
    empty->length = length;
    empty->typePtr = NULL;
    memset(empty->bytes, 0, length + 1);
    return empty;
}

static Jim_Obj *Jim_HexString(Jim_Interp *interp, Jim_Obj *s) {
    int i;
    int len = Jim_Length(s);
    Jim_Obj *hex = Jim_EmptyString(interp,2 * len);

    for (i=0; i<len; i++) {
        sprintf(hex->bytes+(2*i),"%02x",(unsigned char) s->bytes[i]);
    }

    return hex;
}

static int unhex(char c) {
    if (c >= '0' && c <= '9') {
        return (c - '0');
    } else if (c >= 'A' && c <= 'F') {
        return (c - 'A' + 10);
    } else if (c >= 'a' && c <= 'f') {
        return (c - 'a' + 10);
    } else {
        return -1;
    }
}

static Jim_Obj *Jim_Unhex(Jim_Interp *interp, Jim_Obj *hex) {
    int i,b1,b2;
    int err = 0;
    int len = Jim_Length(hex);
    const char *s = Jim_String(hex);

    if ((len % 2) != 0) {
        return NULL;
    }

    Jim_Obj *bin = Jim_EmptyString(interp,len/2);

    for (i=0; i<len/2; i++) {
        if ((b1 = unhex(s[2*i])) == -1 ||
            (b2 = unhex(s[2*i+1])) == -1) {
            ++err;
            break;
        } else {
            bin->bytes[i] = (unsigned char)((b1 * 16) + b2);
        }
    }

    if (err > 0) {
        Jim_FreeNewObj(interp,bin);
        return NULL;
    } else {
        return bin;
   }
}

static int Hexdump_Cmd(Jim_Interp *interp, int argc,
                                   Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<string>");
        return JIM_ERR;
    }

    Jim_SetResult(interp,Jim_HexString(interp,argv[1]));

    return JIM_OK;
}

static int Unhexdump_Cmd(Jim_Interp *interp, int argc,
                                   Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<string>");
        return JIM_ERR;
    }

    Jim_Obj *s = Jim_Unhex(interp,argv[1]);
    if (s == NULL) {
        Jim_SetResultString(interp,"Invalid hex string",-1);
        return JIM_ERR;
    } else {
        Jim_SetResult(interp,s);
        return JIM_OK;
    }
}

static Jim_Obj *Jim_Zbase32String(Jim_Interp *interp, Jim_Obj *s) {
    int len = Jim_Length(s);
    Jim_Obj *encoded = Jim_EmptyString(interp,2 * len);
    encoded->length = zbase32_encode((unsigned char *)encoded->bytes,
                                     (const unsigned char *)Jim_String(s),
                                     (unsigned int)len*8);
    return encoded;
}

static Jim_Obj *Jim_UnZbase32String(Jim_Interp *interp, Jim_Obj *s) {
    int len = Jim_Length(s);
    int bits = len * 5;
    bits -= bits % 8;
    Jim_Obj *decoded = Jim_EmptyString(interp,len);
    decoded->length = zbase32_decode((unsigned char *)decoded->bytes,
                                     (const unsigned char *)Jim_String(s),
                                     bits);
    return decoded;
}

static int UnZbase32_Cmd(Jim_Interp *interp, int argc,
                         Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<string>");
        return JIM_ERR;
    }

    Jim_SetResult(interp,Jim_UnZbase32String(interp,argv[1]));

    return JIM_OK;
}


static int Zbase32_Cmd(Jim_Interp *interp, int argc,
                                   Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<string>");
        return JIM_ERR;
    }

    Jim_SetResult(interp,Jim_Zbase32String(interp,argv[1]));

    return JIM_OK;
}
static int RandomBytes_Cmd(Jim_Interp *interp, int argc, 
                           Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<bytes>");
        return JIM_ERR;
    }

    long len;
    if (Jim_GetLong(interp, argv[1], &len) != JIM_OK) {
        Jim_SetResultString(interp,"Invalid length",-1);
        return JIM_ERR;
    }

    Jim_Obj *random = Jim_EmptyString(interp,len);

    randombytes(random->bytes, (unsigned long long)len);

    Jim_SetResult(interp,random);

    return JIM_OK;
}

static int Stream_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    long keygen = 0;
    char buf[10];
    Jim_Obj *nonce_arg = NULL;
    while (argc > 1 && Jim_String(argv[1])[0] == '-') {
        if (Jim_CompareStringImmediate(interp, argv[1], "-hex")) {
            hex = 1;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-keygen") &&
                       argc > 2) {
            if (Jim_GetLong(interp, argv[2], &keygen) != JIM_OK) {
                Jim_SetResultString(interp,"Invalid keygen length",-1);
                return JIM_ERR;
            }
            --argc;
            ++argv;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-nonce") &&
                       argc > 2) {
            if (Jim_Length(argv[2]) != crypto_stream_NONCEBYTES) {
                snprintf(buf,sizeof(buf),"%d",crypto_stream_NONCEBYTES);
                Jim_SetResultFormatted(interp,
                       "Invalid nonce length [should be %s bytes]",buf);
                return JIM_ERR;
            }
            nonce_arg = argv[2];
            --argc;
            ++argv;
        } else {
            break;
        }
        --argc;
        ++argv;
    }

    if (keygen == 0) {
        if (argc != 3) {
            goto arg_error;
        }
    } else {
        if (argc != 2) {
            goto arg_error;
        }
    }

    if (Jim_Length(argv[1]) != crypto_stream_KEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_stream_KEYBYTES);
        Jim_SetResultFormatted(interp,
                               "Invalid key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *n;

    if (nonce_arg != NULL) {
        n = Jim_DuplicateObj(interp,nonce_arg);
    } else {
        n = Jim_EmptyString(interp,crypto_stream_NONCEBYTES);
        randombytes(n->bytes,(unsigned long long)crypto_stream_NONCEBYTES);
    }

    Jim_Obj *k = argv[1];
    Jim_Obj *m;
    Jim_Obj *c;

    if (keygen == 0) {
        m = argv[2];
        int mlen = Jim_Length(m);
        c = Jim_EmptyString(interp,mlen);

        crypto_stream_xor(c->bytes, m->bytes, (unsigned long long)mlen,
                             n->bytes, k->bytes);
    } else {
        c = Jim_EmptyString(interp,keygen);
        crypto_stream(c->bytes, (unsigned long long)keygen,
                             n->bytes, k->bytes);
    }

    Jim_Obj *result = Jim_NewListObj(interp,NULL,0);

    if (hex == 1) {
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,n)); 
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,c)); 
        Jim_DecrRefCount(interp,n);
        Jim_DecrRefCount(interp,c);
    } else {
        Jim_ListAppendElement(interp,result,n); 
        Jim_ListAppendElement(interp,result,c); 
    }

    Jim_SetResult(interp,result);

    return JIM_OK;

arg_error:
    Jim_WrongNumArgs(interp,1,argv,
            "[-hex] [-nonce <nonce>] [-keygen <len>] <key> [<message>]");
    return JIM_ERR;
}

static int SecretBoxOpen_Cmd(Jim_Interp *interp, int argc, 
                             Jim_Obj *const argv[]) {

    int hex = 0;
    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 4) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex] <key> <nonce> <message>");
        return JIM_ERR;
    }

    Jim_Obj *key = argv[1];
    Jim_Obj *nonce = argv[2];
    Jim_Obj *secretbox = argv[3];

    int pad_len = Jim_Length(secretbox) + crypto_secretbox_BOXZEROBYTES;

    Jim_Obj *secretbox_pad= Jim_EmptyString(interp,pad_len);
    Jim_Obj *msg_pad= Jim_EmptyString(interp,pad_len);

    memcpy(secretbox_pad->bytes + crypto_secretbox_BOXZEROBYTES,
           secretbox->bytes,
           secretbox->length);

    int err = crypto_secretbox_open(msg_pad->bytes,
                                    secretbox_pad->bytes,
                                    (unsigned long long)pad_len,
                                    nonce->bytes,
                                    key->bytes);

    if (err == 0) {
        Jim_Obj *msg = Jim_NewStringObj(interp,
                        msg_pad->bytes + crypto_secretbox_ZEROBYTES,
                        msg_pad->length - crypto_secretbox_ZEROBYTES);

        if (hex) {
            Jim_SetResult(interp,Jim_HexString(interp,msg)); 
            Jim_DecrRefCount(interp,msg);
        } else {
            Jim_SetResult(interp,msg);
        }
    } else {
        Jim_SetResultString(interp,"ERROR: Invalid secretbox",-1);
    }

    Jim_DecrRefCount(interp,secretbox_pad);
    Jim_DecrRefCount(interp,msg_pad);

    return (err == 0) ? JIM_OK : JIM_ERR;
}

static int SecretBox_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];
    Jim_Obj *nonce_arg = NULL;

    while (argc > 1 && Jim_String(argv[1])[0] == '-') {
        if (Jim_CompareStringImmediate(interp, argv[1], "-hex")) {
            hex = 1;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-nonce") &&
                   argc > 2) {
            if (Jim_Length(argv[2]) != crypto_secretbox_NONCEBYTES) {
                snprintf(buf,sizeof(buf),"%d",crypto_secretbox_NONCEBYTES);
                Jim_SetResultFormatted(interp,
                       "Invalid nonce length [should be %s bytes]",buf);
                return JIM_ERR;
            }
            nonce_arg = argv[2];
            --argc;
            ++argv;
        } else {
            break;
        }
        --argc;
        ++argv;
    }

    if (argc != 3) {
        goto arg_error;
    }

    if (Jim_Length(argv[1]) != crypto_secretbox_KEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_secretbox_KEYBYTES);
        Jim_SetResultFormatted(interp,
                               "Invalid key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *key = argv[1];
    Jim_Obj *msg = argv[2];
    int len = Jim_Length(msg);

    Jim_Obj *nonce;

    if (nonce_arg != NULL) {
        nonce = Jim_DuplicateObj(interp,nonce_arg);
    } else {
        nonce = Jim_EmptyString(interp,crypto_secretbox_NONCEBYTES);
        randombytes(nonce->bytes, 
                    (unsigned long long)crypto_secretbox_NONCEBYTES);
    }

    Jim_Obj *msg_pad = Jim_EmptyString(interp,
                                     len + crypto_secretbox_ZEROBYTES);
    Jim_Obj *secretbox_pad = Jim_EmptyString(interp,
                                     len + crypto_secretbox_ZEROBYTES);

    memcpy(msg_pad->bytes + crypto_secretbox_ZEROBYTES,msg->bytes,len);

    crypto_secretbox(secretbox_pad->bytes,
                     msg_pad->bytes,
                     (unsigned long long)msg_pad->length,
                     nonce->bytes,
                     key->bytes);

    Jim_Obj *secretbox = Jim_NewStringObj(interp,
                       secretbox_pad->bytes + crypto_secretbox_BOXZEROBYTES,
                       secretbox_pad->length - crypto_secretbox_BOXZEROBYTES);

    Jim_Obj *result = Jim_NewListObj(interp,NULL,0);

    if (hex == 1) {
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,nonce)); 
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,secretbox)); 
        Jim_DecrRefCount(interp,nonce);
        Jim_DecrRefCount(interp,secretbox);
    } else {
        Jim_ListAppendElement(interp,result,nonce); 
        Jim_ListAppendElement(interp,result,secretbox); 
    }

    Jim_SetResult(interp,result);

    Jim_DecrRefCount(interp,msg_pad);
    Jim_DecrRefCount(interp,secretbox_pad);

    return JIM_OK;

arg_error:
    Jim_WrongNumArgs(interp,1,argv,"[-hex] [-nonce <nonce>] <key> <message>");
    return JIM_ERR;
}

static int BoxOpen_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }
    if (argc != 5) {
        Jim_WrongNumArgs(interp,1,argv,
                     "[-hex] <sender_pk> <recipient_sk> <nonce> <message>");
        return JIM_ERR;
    }

    Jim_Obj *pk = argv[1];
    Jim_Obj *sk = argv[2];
    Jim_Obj *nonce = argv[3];
    Jim_Obj *box = argv[4];

    int pad_len = Jim_Length(box) + crypto_box_BOXZEROBYTES;

    Jim_Obj *box_pad= Jim_EmptyString(interp,pad_len);
    Jim_Obj *msg_pad= Jim_EmptyString(interp,pad_len);

    memcpy(box_pad->bytes + crypto_box_BOXZEROBYTES,
           box->bytes,
           box->length);

    int err = crypto_box_open(msg_pad->bytes,
                              box_pad->bytes,
                              (unsigned long long)pad_len,
                              nonce->bytes,
                              pk->bytes,
                              sk->bytes);

    if (err == 0) {
        Jim_Obj *msg = Jim_NewStringObj(interp,
                        msg_pad->bytes + crypto_box_ZEROBYTES,
                        msg_pad->length - crypto_box_ZEROBYTES);

        if (hex) {
            Jim_SetResult(interp,Jim_HexString(interp,msg)); 
            Jim_DecrRefCount(interp,msg);
        } else {
            Jim_SetResult(interp,msg);
        }
    } else {
        Jim_SetResultString(interp,"ERROR: Invalid box",-1);
    }

    Jim_DecrRefCount(interp,box_pad);
    Jim_DecrRefCount(interp,msg_pad);

    return (err == 0) ? JIM_OK : JIM_ERR;
}

static int Box_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];
    Jim_Obj *nonce_arg = NULL;

    while (argc > 1 && Jim_String(argv[1])[0] == '-') {
        if (Jim_CompareStringImmediate(interp, argv[1], "-hex")) {
            hex = 1;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-nonce")) {
            if (argc > 2) {
                if (Jim_Length(argv[2]) != crypto_box_NONCEBYTES) {
                    snprintf(buf,sizeof(buf),"%d",crypto_box_NONCEBYTES);
                    Jim_SetResultFormatted(interp,
                           "Invalid nonce length [should be %s bytes]",buf);
                    return JIM_ERR;
                }
                nonce_arg = argv[2];
                --argc;
                ++argv;
            } else {
                goto arg_error;
            }
        } else {
            break;
        }
        --argc;
        ++argv;
    }

    if (argc != 4) {
        goto arg_error;
    }

    Jim_Obj *pk= argv[1];
    Jim_Obj *sk = argv[2];
    Jim_Obj *msg = argv[3];
    int len = Jim_Length(msg);

    if (Jim_Length(pk) != crypto_box_PUBLICKEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_box_PUBLICKEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid public key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    if (Jim_Length(sk) != crypto_box_SECRETKEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_box_SECRETKEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid secret key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *nonce;

    if (nonce_arg != NULL) {
        nonce = Jim_DuplicateObj(interp,nonce_arg);
    } else {
        nonce = Jim_EmptyString(interp,crypto_box_NONCEBYTES);
        randombytes(nonce->bytes, (unsigned long long)crypto_box_NONCEBYTES);
    }

    Jim_Obj *msg_pad = Jim_EmptyString(interp,len + crypto_box_ZEROBYTES);
    Jim_Obj *box_pad = Jim_EmptyString(interp,len + crypto_box_ZEROBYTES);

    memcpy(msg_pad->bytes + crypto_box_ZEROBYTES,msg->bytes,len);

    crypto_box(box_pad->bytes,
               msg_pad->bytes,
               (unsigned long long)msg_pad->length,
               nonce->bytes,
               pk->bytes,
               sk->bytes);

    Jim_Obj *box = Jim_NewStringObj(interp,
                       box_pad->bytes + crypto_box_BOXZEROBYTES,
                       box_pad->length - crypto_box_BOXZEROBYTES);

    Jim_Obj *result = Jim_NewListObj(interp,NULL,0);
    if (hex == 1) {
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,nonce)); 
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,box)); 
        Jim_DecrRefCount(interp,nonce);
        Jim_DecrRefCount(interp,box);
    } else {
        Jim_ListAppendElement(interp,result,nonce); 
        Jim_ListAppendElement(interp,result,box); 
    }

    Jim_SetResult(interp,result);

    Jim_DecrRefCount(interp,msg_pad);
    Jim_DecrRefCount(interp,box_pad);

    return JIM_OK;

arg_error:
    Jim_WrongNumArgs(interp,1,argv,
             "[-hex] [-nonce <nonce>] <recipient_pk> <sender_sk> <message>");
    return JIM_ERR;
}

static int Hash_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    int sha256 = 0;

    while (argc > 1 && Jim_String(argv[1])[0] == '-') {
        if (Jim_CompareStringImmediate(interp, argv[1], "-hex")) {
            hex = 1;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-sha256")) {
            sha256 = 1;
        } else if (Jim_CompareStringImmediate(interp, argv[1], "-sha512")) {
            sha256 = 0;
        } else {
            break;
        }
        --argc;
        ++argv;
    }

    if (argc != 2) {
        goto arg_error;
    }

    Jim_Obj *msg = argv[1];

    Jim_Obj *hash;
    
    if (sha256) {
        hash = Jim_EmptyString(interp,crypto_hash_sha256_BYTES);
        crypto_hash_sha256(hash->bytes,msg->bytes,
                                (unsigned long long)msg->length);
    } else {
        hash = Jim_EmptyString(interp,crypto_hash_sha512_BYTES);
        crypto_hash(hash->bytes,msg->bytes,
                                (unsigned long long)msg->length);
    }

    if (hex == 1) {
        Jim_SetResult(interp,Jim_HexString(interp,hash));
        Jim_DecrRefCount(interp,hash);
    } else {
        Jim_SetResult(interp,hash);
    }

    return JIM_OK;

arg_error:
    Jim_WrongNumArgs(interp,1,argv,"[-hex] [-sha256|-sha512] <message>");
    return JIM_ERR;

}

static int BoxKeypair_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;

    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 1) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex]");
        return JIM_ERR;
    }

    Jim_Obj *pk = Jim_EmptyString(interp,crypto_box_PUBLICKEYBYTES);
    Jim_Obj *sk = Jim_EmptyString(interp,crypto_box_SECRETKEYBYTES);

    crypto_box_keypair(pk->bytes,sk->bytes);

    Jim_Obj *result = Jim_NewListObj(interp,NULL,0);

    if (hex == 1) {
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,pk)); 
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,sk)); 
        Jim_DecrRefCount(interp,pk);
        Jim_DecrRefCount(interp,sk);
    } else {
        Jim_ListAppendElement(interp,result,pk); 
        Jim_ListAppendElement(interp,result,sk); 
    }

    Jim_SetResult(interp,result);

    return JIM_OK;
}

static int SignKeypair_Cmd(Jim_Interp *interp, int argc, 
                           Jim_Obj *const argv[]) {

    int hex = 0;

    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 1) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex]");
        return JIM_ERR;
    }

    Jim_Obj *pk = Jim_EmptyString(interp,crypto_sign_PUBLICKEYBYTES);
    Jim_Obj *sk = Jim_EmptyString(interp,crypto_sign_SECRETKEYBYTES);

    crypto_sign_keypair(pk->bytes,sk->bytes);

    Jim_Obj *result = Jim_NewListObj(interp,NULL,0);

    if (hex == 1) {
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,pk)); 
        Jim_ListAppendElement(interp,result,Jim_HexString(interp,sk)); 
        Jim_DecrRefCount(interp,pk);
        Jim_DecrRefCount(interp,sk);
    } else {
        Jim_ListAppendElement(interp,result,pk); 
        Jim_ListAppendElement(interp,result,sk); 
    }

    Jim_SetResult(interp,result);

    return JIM_OK;
}

static int Sign_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];

    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 3) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex] <sender_sk> <msg>");
        return JIM_ERR;
    }

    Jim_Obj *sk = argv[1];
    Jim_Obj *m = argv[2];
    int mlen = Jim_Length(m);
    unsigned long long smlen;

    if (Jim_Length(sk) != crypto_sign_SECRETKEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_sign_SECRETKEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid secret key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *sm = Jim_EmptyString(interp,mlen + crypto_sign_BYTES);

    crypto_sign(sm->bytes,&smlen,m->bytes,(unsigned long long)mlen,sk->bytes);

    memset(sm->bytes + (int)smlen, 0, sm->length - (int)smlen);
    sm->length = (int)smlen;

    if (hex == 1) {
        Jim_SetResult(interp,Jim_HexString(interp,sm));
        Jim_DecrRefCount(interp,sm);
    } else {
        Jim_SetResult(interp,sm);
    }

    return JIM_OK;
}

static int SignOpen_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];

    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 3) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex] <sender_pk> <signed_msg>");
        return JIM_ERR;
    }

    Jim_Obj *pk = argv[1];
    Jim_Obj *sm = argv[2];
    int smlen = Jim_Length(sm);
    unsigned long long mlen;

    if (Jim_Length(pk) != crypto_sign_PUBLICKEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_sign_PUBLICKEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid public key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *m = Jim_EmptyString(interp,smlen);

    if (crypto_sign_open(m->bytes,&mlen,sm->bytes,smlen,pk->bytes) == -1) {
        Jim_DecrRefCount(interp,m);
        Jim_SetResultString(interp,"ERROR: Invalid signature",-1);
        return JIM_ERR;
    }

    memset(m->bytes + (int)mlen, 0, m->length - (int)mlen);
    m->length = (int)mlen;

    if (hex == 1) {
        Jim_SetResult(interp,Jim_HexString(interp,m));
        Jim_DecrRefCount(interp,m);
    } else {
        Jim_SetResult(interp,m);
    }

    return JIM_OK;
}

static int Auth_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];

    if (argc > 1 && Jim_CompareStringImmediate(interp,argv[1],"-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 3) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex] <key> <msg>");
        return JIM_ERR;
    }

    Jim_Obj *k = argv[1];
    Jim_Obj *m = argv[2];
    int mlen = Jim_Length(m);

    if (Jim_Length(k) != crypto_auth_KEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_auth_KEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *a = Jim_EmptyString(interp,crypto_auth_BYTES);

    crypto_auth(a->bytes,m->bytes,(unsigned long long)mlen,k->bytes);

    if (hex == 1) {
        Jim_SetResult(interp,Jim_HexString(interp,a));
        Jim_DecrRefCount(interp,a);
    } else {
        Jim_SetResult(interp,a);
    }

    return JIM_OK;
}

static int AuthVerify_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;
    char buf[10];

    if (argc != 4) {
        Jim_WrongNumArgs(interp,1,argv,"<key> <auth> <msg>");
        return JIM_ERR;
    }

    Jim_Obj *k = argv[1];
    Jim_Obj *a = argv[2];
    Jim_Obj *m = argv[3];
    int mlen = Jim_Length(m);

    if (Jim_Length(k) != crypto_auth_KEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_auth_KEYBYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    if (Jim_Length(a) != crypto_auth_BYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_auth_BYTES);
        Jim_SetResultFormatted(interp,
                   "Invalid auth length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    if (crypto_auth_verify(a->bytes,m->bytes,
                           (unsigned long long)mlen,k->bytes) == -1) {
        Jim_SetResultString(interp,"ERROR: Invalid authenticator",-1);
        return JIM_ERR;
    } else {
        return JIM_OK;
    }
}

Jim_naclInit(Jim_Interp *interp) {
    Jim_CreateCommand(interp, "hexdump", Hexdump_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "unhexdump", Unhexdump_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "zbase32", Zbase32_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "unzbase32", UnZbase32_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "randombytes", RandomBytes_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "hash", Hash_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "stream", Stream_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "box_keypair", BoxKeypair_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "box", Box_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "box_open", BoxOpen_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "secretbox", SecretBox_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "secretbox_open", SecretBoxOpen_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "sign_keypair", SignKeypair_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "sign", Sign_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "sign_open", SignOpen_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "auth", Auth_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "auth_verify", AuthVerify_Cmd, NULL, NULL);
}

