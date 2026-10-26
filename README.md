# QConsent

Quantum secure, revocable, verifiable patient consent for healthcare, with no patient data on the chain.

QConsent is a quantum secure record of patient consent for healthcare. It proves which patient consented, to which clinician or organisation, for which purposes, over which categories of health data, from when until when, and whether and when that consent was withdrawn. Every consent, every acknowledgement by the grantee and every revocation is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and each can carry a Qstamp time proof recorded on the Quantova network. No patient data ever leaves the holder. The chain sees only a commitment and a time proof, never a name, a record number or a diagnosis.

## At a glance

1. A patient signs a consent naming the grantee, the purposes, the categories of health data and the period of validity.
2. The grantee can sign an acknowledgement, and the patient can sign a revocation at any time.
3. Every record is signed with the post quantum algorithm ML-DSA-65 under FIPS 204.
4. Each record is anchored on the Quantova network for an independent time proof, under the healthcare record kind 1201, so an explorer indexes QConsent records as their own category.
5. The chain holds only a salted commitment and the time proof. No name, record number, diagnosis, purpose or category ever reaches the chain.
6. Any party verifies a record for itself against the patient key it expects, with no trust in the hospital or the patient.

## Quantum secure

The signatures QConsent produces are post quantum. ML-DSA-65 rests on the hardness of lattice problems that a large quantum computer is not known to break, unlike the RSA and elliptic curve signatures that most consent and records systems rely on today. A consent signed now stays provable for the full lifetime of the record it supports, which in healthcare can be the lifetime of the patient and beyond. A record signed with a classical scheme loses that guarantee the day a quantum computer can forge it, and every consent ever signed under it becomes deniable at once. QConsent is built so that the authority behind a disclosure of health data remains provable long after that day.

## What QConsent is

A patient grants a clinician, a hospital, a laboratory or a research programme access to defined categories of their health data, for defined purposes, for a defined period. When a disclosure is later questioned, three questions decide it. Did the patient consent. To whom, for what and for how long. And was the consent still in force when the data was used.

QConsent answers all three with cryptographic evidence. The patient holds a key and signs a consent that names the grantee key, the purposes the data may be used for, the categories of data covered and the period of validity. The grantee may sign an acknowledgement that binds it to the exact consent it received. The patient may at any time sign a revocation that withdraws the consent. A verifier, whether an auditor, a data protection authority, an ethics board or a court, can then confirm that the patient consented, to that grantee, for those purposes, within that period and before any revocation, without trusting the hospital or the patient, and the time of each record counts as proven only through a finality certificate of the network validators or official endpoints of two independent operators, never through one endpoint alone.

QConsent is standalone. It runs on the systems of the care provider or the patient, holds its keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## Why healthcare needs it

Health data is the most sensitive category of personal data under every major regime. The Health Insurance Portability and Accountability Act in the United States requires a provider to hold a patient authorisation for most disclosures of protected health information and to show it on request. The Act on the Protection of Personal Information in Japan treats medical history as information requiring special care and requires the patient consent for its handling and transfer. The Personal Information Protection Act in Korea requires separate, explicit consent for the processing of health information. Article 9 of the General Data Protection Regulation in the European Union forbids processing of health data unless an exception such as the explicit consent of the patient applies, and Article 7 requires the controller to be able to demonstrate that consent was given.

Consent recorded only in a hospital database cannot carry that weight, because the hospital can alter it and because nothing in it proves that the consent existed, and in which form, before the data was used. Consent on paper is worse, because it cannot be checked at the speed at which data now moves between systems, laboratories, insurers and research networks. QConsent gives a record of consent that the holder cannot backdate or quietly change, that any party can verify for itself, and that stays provable with post quantum signatures for the full retention period of the health record it supports.

## Who uses it

1. Hospitals and clinics that disclose records to other providers, to insurers or to patients.
2. General practitioners and specialists who refer patients and share histories.
3. Laboratories and imaging centres that release results to the requesting clinician and to the patient.
4. Research programmes and biobanks that must prove informed consent for every dataset they hold.
5. Health information exchanges and national record networks that route data between many organisations.
6. Insurers and regulators that need to confirm that a given disclosure of health data was consented to.

## How a provider integrates QConsent

1. Give every patient a key. Each patient receives an ML-DSA-65 key created with the keygen command or the generateKey function and held by the patient, in a Quantova wallet or a provider held custodial store under the control of the patient. The key identifies the patient only as a pseudonymous key id, never by name.

2. Give every grantee a key. A clinician, a hospital department, a laboratory or a research programme holds its own ML-DSA-65 key in its secrets manager or hardware protected store.

3. Grant consent. The patient signs a consent naming the grantee key, the purposes the data may be used for, the categories of data covered and the period of validity. Purposes and categories are short code words agreed between the parties, such as diagnosis, treatment, research or billing for purposes and allergies, medications, imaging or genetics for categories. The consent is anchored on the Quantova network, which proves that the consent existed and in which form before the data was used, and the anchor carries a deadline no later than the expiry of the consent, so the chain itself refuses to record it late.

4. Acknowledge receipt. The grantee may sign an acknowledgement that names the exact consent it received and the time it received it, so the grantee cannot later deny the terms it was given. The acknowledgement is anchored in the same way.

5. Use the consent to gate a disclosure. Before data is released, the system calls status with the consent, the key id of the grantee asking for the data and any revocations it holds. The call reads the time of the chain and returns whether the consent is active at that moment, with the purposes and categories it covers, so a disclosure is released only inside the terms the patient signed and only while the consent is in force.

6. Revoke when the patient withdraws. The patient signs and anchors a revocation. Every use of the data after it is shown to be outside consent, and uses before it remain covered. While a revocation has no proven time, the consent is treated as indeterminate rather than active, so data is never released on the assumption that a withdrawal came later.

7. Verify when evidence is needed. The provider hands the consent, any acknowledgement, any revocations to the party that asks. That party verifies them against the patient key it expects, with the verify command, the library or the independent procedure. Verification always requires the expected envelope type and, for a consent, the expected patient, so a consent signed by any other key is rejected and a consent can never pass where a revocation is expected.

## What is published and what stays private

Consents, acknowledgements and revocations stay with the provider and the parties it chooses to share them with. The chain holds only a salted SHA3 commitment to each record and its time proof, recorded under the healthcare record kind 1201, so an explorer can index and count QConsent records without seeing any of their content. No name, record number, diagnosis, purpose or category is ever written to the chain. Where a provider needs to tie a consent to a patient record without revealing the identity, the grantee computes a subject reference with the subject command, a salted commitment to the patient identity that is the same for the same patient and secret and reveals nothing without the secret.

## Install

```
npm install @quantovainc/qconsent
```

## Library

```js
const qconsent = require('@quantovainc/qconsent');

const patient = qconsent.generateKey();
const hospital = qconsent.generateKey();

const consent = qconsent.grant({
  key: patient,
  grantee: qconsent.describeKey(hospital),
  granteeLabel: 'Tokyo General Hospital',
  purposes: ['diagnosis', 'treatment'],
  categories: ['allergies', 'medications'],
  validUntil: '2027-10-26T00:00:00.000Z',
});

const [anchored] = await qconsent.anchor(consent, { seed, index: 0, network: 'testnet' });

const state = await qconsent.status(anchored, {
  granteeKeyId: qconsent.keyId(hospital),
  revocations: [],
  network: 'testnet',
});
// state.active is true while the consent is in force

const revocation = qconsent.revoke({ key: patient, consent: anchored });
```

The functions are generateKey, publicKey, keyId, describeKey, subjectRef, grant, acknowledge, revoke, status, anchor, complete, verify, consentRef and anchorDigest. Keys are 32 byte seeds that stay with their holder and are wiped with fill(0) after use. The full types are in index.d.ts.

## Command line

```
qconsent keygen patient.key
qconsent key hospital.key > hospital.json
qconsent grant --key patient.key --grantee hospital.json \
  --purpose diagnosis --purpose treatment --category allergies --category medications \
  --valid-until 2027-10-26T00:00:00.000Z --out consent.json
qconsent anchor consent.json --network testnet --seed-file account.key
qconsent status --consent consent.json --network testnet
qconsent revoke --key patient.key --consent consent.json --out revoke.json
qconsent verify consent.json --type consent --network testnet --patient-key-id <id>
```

Labels, notes and the patient identity are read from files or from standard input, never from the command line, so they never appear in the shell history or the process list. Exit codes are 0 for valid or active, 1 for invalid or inactive, 2 for indeterminate or unproven and 64 for usage errors.

## How verification decides

A verifier confirms, in order, that the record is well formed, that its ML-DSA-65 signature is valid, that it was signed by the party it names, that for a consent the patient is the one expected, that the anchor was recorded on the stated network under the record kind and proven by a finality certificate or by two independent operators, that the claimed time is consistent with the anchor time, and for a consent that it is in force at the time of the check and has not been revoked. A result is valid only when every check passes. An anchor confirmed by a single endpoint, or by endpoints that are not pinned independent operators, is never valid. The time of a record is never taken from one endpoint alone.

## Standards

QConsent signs with ML-DSA-65, the parameter set of the Module Lattice Digital Signature Algorithm standardised in FIPS 204. Records are canonical binary before signing, so a record has exactly one valid encoding. Time proofs are recorded through Qstamp on the Quantova network. QConsent carries no health data on the chain and is designed to support, not replace, the consent duties of HIPAA in the United States, the Act on the Protection of Personal Information in Japan, the Personal Information Protection Act in Korea and Articles 7 and 9 of the General Data Protection Regulation in the European Union.

## License

Apache License 2.0 or MIT, at your option.
