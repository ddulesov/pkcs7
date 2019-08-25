#!/bin/sh
## GENERATE test set 
##  cert*.pem - Certificate Authority  certificate
##  key*.pem - Certificate Authority private key
##  *.client.crt -  signer certificate
##  *.cms  - signer CMS 

echo "test string" > sign.data

#create client certificates

#RSA 256 ---------------------------
#ca
openssl req -x509 -newkey rsa:2048 -keyout keyRSA256.pem -out certRSA256.pem -nodes -days 3650 -subj '/CN=localhost/OU=256'

#client csr
openssl req -nodes -newkey rsa:2048 -keyout RSA256.client.key -out RSA256.client.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com"

#sign
openssl x509 -req -in RSA256.client.csr -CA certRSA256.pem -CAkey keyRSA256.pem -CAcreateserial -out RSA256.client.crt -days 365 -sha256

#create cms
openssl cms -sign -nosmimecap -md sha256 -nodetach -binary -in sign.data -signer RSA256.client.crt -inkey RSA256.client.key -out RSA256.cms -outform PEM
#openssl cms -engine gost -cmsout -in RSA256.cms -inform PEM -print

#RSA 512 ---------------------------
#ca
openssl req -x509 -newkey rsa:4096 -keyout keyRSA512.pem -sha512 -out certRSA512.pem -nodes -days 3650 -subj '/CN=localhost/OU=512'

#client csr
openssl req -nodes -newkey rsa:2048 -keyout RSA512.client.key -sha512 -out RSA512.client.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com"
#sign
openssl x509 -req -in RSA512.client.csr -CA certRSA512.pem -CAkey keyRSA512.pem -CAcreateserial -out RSA512.client.crt -days 365 -sha512

#create cms
openssl cms -sign -nosmimecap -md sha512 -nodetach -binary -in sign.data -signer RSA512.client.crt -inkey RSA512.client.key -out RSA512.cms -outform PEM

#GOST 34.10-2001---------------------------
#ca 
openssl req  -engine gost -x509 -newkey gost2001 -pkeyopt paramset:A  -keyout keyGOST2001.pem  -out certGOST2001.pem -nodes -days 3650   -subj "/CN=localhost/OU=gost2001" 


#client csr
openssl req -engine gost -nodes -newkey gost2001 -pkeyopt paramset:A -keyout GOST2001.client.key -out GOST2001.client.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com"

#sign
openssl x509 -engine gost -req -in GOST2001.client.csr -CA certGOST2001.pem -CAkey keyGOST2001.pem -CAcreateserial -out GOST2001.client.crt -days 365 


#create cms
openssl cms -sign  -engine gost -nosmimecap  -nodetach -binary -in sign.data -signer GOST2001.client.crt -inkey GOST2001.client.key -out GOST2001.cms -outform PEM

#GOST 34.10-2012-256---------------------------
#ca
openssl req  -engine gost -x509 -newkey gost2012_256 -pkeyopt paramset:A  -keyout keyGOST2012_256.pem  -out certGOST2012_256.pem -nodes -days 3650   -subj "/CN=localhost/OU=gost2012_256" 

#client csr
openssl req -engine gost -nodes -newkey gost2012_256 -pkeyopt paramset:A -keyout GOST2012_256.client.key -out GOST2012_256.client.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com"

#sign
openssl x509 -engine gost -req -in GOST2012_256.client.csr -CA certGOST2012_256.pem -CAkey keyGOST2012_256.pem -CAcreateserial -out GOST2012_256.client.crt -days 365 

#create cms
openssl cms -sign  -engine gost -nosmimecap  -nodetach -binary -in sign.data -signer GOST2012_256.client.crt -inkey GOST2012_256.client.key -out GOST2012_256.cms -outform PEM

#GOST 34.10-2012-512---------------------------
#ca
openssl req  -engine gost -x509 -newkey gost2012_512 -pkeyopt paramset:A  -keyout keyGOST2012_512.pem  -out certGOST2012_512.pem -nodes -days 3650   -subj "/CN=localhost/OU=gost2012_512" 


#client csr
openssl req -engine gost -nodes -newkey gost2012_512 -pkeyopt paramset:A -keyout GOST2012_512.client.key -out GOST2012_512.client.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=Global Security/OU=IT Department/CN=dmitry.dulesov@gmail.com"

#sign
openssl x509 -engine gost -req -in GOST2012_512.client.csr -CA certGOST2012_512.pem -CAkey keyGOST2012_512.pem -CAcreateserial -out GOST2012_512.client.crt -days 365 

#create cms
openssl cms -sign  -engine gost -nosmimecap  -nodetach -binary -in sign.data -signer GOST2012_512.client.crt -inkey GOST2012_512.client.key -out GOST2012_512.cms -outform PEM



