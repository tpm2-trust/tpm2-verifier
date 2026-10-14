# Submissions

Help extend the vendor store: send the output of `tpm2-verifier debug-anon` from
a TPM whose vendor is missing or incomplete.

```bash
sudo tpm2-verifier debug-anon -o tpm2-verifier-debug-anon.tar.gz
```

It contains no data that identifies your TPM: no EK certificate, no
per-device CA certificate, no serial numbers, keys or NV content (see the
README of the repository). Check the list it prints before sending.

Submit it either

- as a pull request adding the file to this directory (CI runs
  `tpm2-verifier vendor review` on it and shows the result in the job summary), or
- attached to an issue using the "TPM vendor submission" template.

Do **not** put full `tpm2-verifier debug` bundles here: they contain the EK
certificate, which identifies your machine. If a maintainer asks for one,
send it privately.

The maintainer imports a submission with

```bash
tpm2-verifier vendor review submissions/<file>
tpm2-verifier vendor import [-accept <sha256>]... submissions/<file>
git rm submissions/<file>
```
