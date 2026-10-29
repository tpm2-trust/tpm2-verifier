# Intel PTT (OnDie CA)

Thanks to the [Intel community thread](https://community.intel.com/t5/Mobile-and-Desktop-Processors/How-to-verify-an-Intel-PTT-endorsement-key-certificate/td-p/1603153/page/2)
and [@fblaese](https://github.com/fblaese), from which the original
[intel-ek-dechainer](https://github.com/tpm2-trust/ek-dechainer) emerged.

## Hierarchy

```
depth=6  OnDie CA Root Cert Signing                    static, roots/ondie-ca-root.der
depth=5  OnDie CA CSME Intermediate CA                 static, intermediates/ondie-ca-csme-intermediate.der
depth=4  On Die CSME P_MCC 00001881 Issuing CA         static, intermediates/mcc-00001881-issuing-ca.der
depth=3  CSME MCC ROM CA                               per device, NV index 0x01C00100
depth=2  CSME MCC SVN01 Kernel CA                      per device, NV index 0x01C00100
depth=1  CSME MCC PTT 01SVN                            per device, NV index 0x01C00100
depth=0  EK certificate (empty subject)                per device, NV index 0x01C00002 / 0x01C0000A
```

### Root CA (static)

```
Download: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer
Subject:  C=US, ST=CA, L=Santa Clara, O=Intel Corporation, OU=OnDie CA Root Cert Signing, CN=www.intel.com
CRL:      https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA.crl  (published for the root's children)
```

### Intermediate 1 (static)

```
Download: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_CSME_Intermediate.cer
Issuer:   ... OU=OnDie CA Root Cert Signing, CN=www.intel.com
Subject:  OU=OnDie CA CSME Intermediate CA, CN=www.intel.com
CRL:      https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA.crl
```

### Intermediate 2 (static)

```
Download: https://tsci.intel.com/content/OnDieCA/certs/MCC_00001881_OnDie_CA.cer
Issuer:   OU=OnDie CA CSME Intermediate CA, CN=www.intel.com
Subject:  OU=On Die CSME P_MCC 00001881 Issuing CA, CN=www.intel.com
CRL:      https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Product.crl
```

### Intermediates 3-5 (per device, read from NV index `0x01C00100`)

The structure is identical on every device, the certificates themselves are not.

```
Intermediate 3
Issuer:     OU=On Die CSME P_MCC 00001881 Issuing CA, CN=www.intel.com
Subject:    CN=CSME MCC ROM CA
CRL:        https://tsci.intel.com/content/OnDieCA/crls/MCC_00001881_OnDie_CA.crl

Intermediate 4
Issuer:     CN=CSME MCC ROM CA
Subject:    CN=CSME MCC SVN01 Kernel CA
CRL:        https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
CRL Issuer: DirName: OU=OnDie CA CSME Intermediate CA, CN=www.intel.com

Intermediate 5
Issuer:     CN=CSME MCC SVN01 Kernel CA
Subject:    CN=CSME MCC PTT 01SVN
CRL:        https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
CRL Issuer: DirName: OU=OnDie CA CSME Intermediate CA, CN=www.intel.com
```

`OnDie_CA_CSME_Indirect.crl` is an *indirect* CRL: it is signed by the
"OnDie CA CSME Intermediate CA" but covers certificates issued by the per-device
CAs. With openssl this needs `-extended_crl`.

## Quirks

- The EK certificate has an empty subject; the TPM identity lives in a critical
  subjectAltName `directoryName` (TCG attributes 2.23.133.2.1-3).
- Older PTT generations have no EK certificate in NV; `tpm2_getekcertificate`
  can download it from Intel's online EK service instead.
