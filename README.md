# hsm-ca-manager

## compile

```sh
$ make
```
## run
### create root CA
```sh
$ bash gen_root_ca.sh
```
## Example
```sh
$ make
cc -Wall -O2   -c -o gen_root_ca_cert.o gen_root_ca_cert.c
cc -o gen_root_ca_cert gen_root_ca_cert.o -lcrypto
$ bash gen_root_ca.sh
Using slot 0 with a present token (0x0)
Logging in to "test (UserPIN)".
Please enter User PIN: 
Key pair generated:
Private Key Object; RSA 
  label:      Private Key
  ID:         10
  Usage:      decrypt, sign
  Access:     none
Public Key Object; RSA 4096 bits
  label:      Private Key
  ID:         10
  Usage:      encrypt, verify
  Access:     none
Enter PKCS#11 token PIN for test (UserPIN):
Using slot 0 with a present token (0x0)
Logging in to "test (UserPIN)".
Please enter User PIN: 
Created certificate:
Certificate Object; type = X.509 cert
  label:      Certificate
  subject:    DN: C=KR, O=test org, CN=test root CA
  ID:         10
$ ls root_ca.pem root_ca.der
root_ca.der  root_ca.pem
$ pkcs15-tool -D
Using reader with a card: ACS ACR1252 Dual Reader [ACR1252 Dual Reader PICC] 00 00
PKCS#15 Card [test]:
        Version        : 0
        Serial number  : xxxxxxxxxxxx
        Manufacturer ID: www.CardContact.de
        Flags          : PRN generation


PIN [UserPIN]
        Object Flags   : [0x03], private, modifiable
        Auth ID        : 02
        ID             : 01
        Flags          : [0x812], local, initialized, exchangeRefData
        Length         : min_len:6, max_len:15, stored_len:0
        Pad char       : 0x00
        Reference      : 129 (0x81)
        Type           : ascii-numeric
        Path           : e82b0601040181c31f0201::
        Tries left     : 3

PIN [SOPIN]
        Object Flags   : [0x01], private
        ID             : 02
        Flags          : [0x9A], local, unblock-disabled, initialized, soPin
        Length         : min_len:16, max_len:16, stored_len:0
        Pad char       : 0x00
        Reference      : 136 (0x88)
        Type           : bcd
        Path           : e82b0601040181c31f0201::
        Tries left     : 15

Private RSA Key [Certificate]
        Object Flags   : [0x03], private, modifiable
        Usage          : [0x0E], decrypt, sign, signRecover
        Access Flags   : [0x1D], sensitive, alwaysSensitive, neverExtract, local
        Algo_refs      : 0
        ModLength      : 4096
        Key ref        : 1 (0x01)
        Native         : yes
        Auth ID        : 01
        ID             : 10
        MD:guid        : 226b0e3e-dba2-9fc1-48fa-cbfe755dcf51

X.509 Certificate [Certificate]
        Object Flags   : [0x00]
        Authority      : no
        Path           : ce01
        ID             : 10
        Encoded serial : 02 01 01
```
