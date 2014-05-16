
#include <jim.h>

#include "tweetnacl.h"

static void _hexdump(const char *s,char *h,int n) {
    int i;
    for (i=0; i<n; i++) {
        sprintf(h+(2*i),"%02x",s[i]);
    }
}

static int Hexdump_Cmd(Jim_Interp *interp, int argc,
                                   Jim_Obj *const argv[]) {
    if (argc != 2) {
        Jim_WrongNumArgs(interp,1,argv,"<string>");
        return JIM_ERR;
    }

    int i;
    int n = Jim_Length(argv[1]);
    const char *s = Jim_String(argv[1]);

    void *h = Jim_Alloc(2*n);
    if (h == NULL) {
        Jim_SetResultString(interp, "Jim_Alloc Error", -1);
        return JIM_ERR;
    }

    _hexdump(s,h,n);

    Jim_SetResultString(interp,h,2*n);
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

    void *r = Jim_Alloc(len);
    if (r == NULL) {
        Jim_SetResultString(interp, "Jim_Alloc Error", -1);
        return JIM_ERR;
    }

    randombytes(r,len);

    Jim_SetResult(interp,Jim_NewStringObjNoAlloc(interp,r,len));

    return JIM_OK;
}

static int SecretBox_Cmd(Jim_Interp *interp, int argc, Jim_Obj *const argv[]) {

    int hex = 0;

    if (argc > 1 && Jim_CompareStringImmediate(interp, argv[1], "-hex")) {
        hex = 1;
        --argc;
        ++argv;
    }

    if (argc != 3) {
        Jim_WrongNumArgs(interp,1,argv,"[-hex] <key> <data>");
        return JIM_ERR;
    }

    char buf[10];
    if (Jim_Length(argv[1]) != crypto_secretbox_KEYBYTES) {
        snprintf(buf,sizeof(buf),"%d",crypto_secretbox_KEYBYTES);
        Jim_SetResultFormatted(interp,
                               "Invalid key length [should be %s bytes]",buf);
        return JIM_ERR;
    }

    Jim_Obj *nonce,*enc,*result;

    unsigned char n[crypto_secretbox_NONCEBYTES];
    randombytes(n,crypto_secretbox_NONCEBYTES);

    int len = Jim_Length(argv[2]);

    void *z = Jim_Alloc(len);
    if (z == NULL) {
        Jim_SetResultString(interp, "Jim_Alloc Error", -1);
        return JIM_ERR;
    }

    crypto_secretbox(z,Jim_String(argv[2]),len,n,Jim_String(argv[1]));
    
    result = Jim_NewListObj(interp,NULL,0);
    if (hex == 1) {
        void *hn = Jim_Alloc(2*crypto_secretbox_NONCEBYTES);
        void *hz = Jim_Alloc(2*len);
        if (hn == NULL || hz == NULL) {
            Jim_SetResultString(interp, "Jim_Alloc Error", -1);
            return JIM_ERR;
        }
        _hexdump(n,hn,crypto_secretbox_NONCEBYTES);
        _hexdump(z,hz,len);
        nonce = Jim_NewStringObjNoAlloc(interp,hn,crypto_secretbox_NONCEBYTES*2);
        enc = Jim_NewStringObjNoAlloc(interp,z,len*2);
    } else {
        nonce = Jim_NewStringObj(interp,n,crypto_secretbox_NONCEBYTES);
        enc = Jim_NewStringObj(interp,z,len);
    }

    Jim_ListAppendElement(interp,result,nonce); 
    Jim_ListAppendElement(interp,result,enc); 

    Jim_SetResult(interp,result);
    return JIM_OK;
}

Jim_naclInit(Jim_Interp *interp)
{
    Jim_CreateCommand(interp, "hexdump", Hexdump_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "secretbox", SecretBox_Cmd, NULL, NULL);
    Jim_CreateCommand(interp, "randombytes", RandomBytes_Cmd, NULL, NULL);
    return JIM_OK;
}

