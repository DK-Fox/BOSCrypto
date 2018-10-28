if [ $1 = 'run' ];then
    python3 BOSCrypto.py -m gen
    python3 BOSCrypto.py -m en -f text -r master-public.pem -o obj -a auth
    python3 BOSCrypto.py -m de -f text1 -r master-private.pem -o obj -a auth
fi
if [ $1 = 'rm'  ];then
    rm master-public.pem master-private.pem text1 obj auth
fi
