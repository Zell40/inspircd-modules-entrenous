# m_account_registration (InspIRCd 4)

Module extra pour [draft/account-registration](https://ircv3.net/specs/extensions/account-registration) : commandes `REGISTER` / `VERIFY`, cap `draft/account-registration`, codes FAIL de la spec.

L’ircd ne stocke **pas** les comptes. Comme `m_sasl`, il transmet la requête aux services via `ENCAP ACCREG`. Sans module services correspondant, `REGISTER` aboutit à `FAIL … TEMPORARILY_UNAVAILABLE` après le timeout.

## Installation

1. Copier `m_account_registration.cpp` dans `src/modules/` de ton arbre InspIRCd 4.
2. Recompiler (`make`).
3. Charger **après** `cap` et `account` (et `sasl` si tu utilises require-sasl) :

```xml
<module name="cap">
<module name="account">
<module name="sasl">
<module name="account_registration">

<sasl target="services.example.net">

<accountregistration
    target="services.example.net"
    beforeconnect="yes"
    emailrequired="no"
    customaccountname="no"
    minpasswordlength="4"
    maxpasswordlength="300"
    accountrequired="no"
    timeout="15s">
```

`target` doit être le nom du serveur de services (identique à `<sasl:target>`).

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `target` | (obligatoire) | Serveur services qui reçoit `ENCAP ACCREG` |
| `beforeconnect` | yes | Annonce `before-connect` ; `REGISTER`/`VERIFY` avant le 001 |
| `emailrequired` | no | Annonce `email-required` ; refuse `*` comme email |
| `customaccountname` | no | Si no, le compte doit être le nick (ou `*`) |
| `minpasswordlength` | 1 | Annoncé dans la valeur de cap |
| `maxpasswordlength` | 300 | Annoncé dans la valeur de cap |
| `accountrequired` | no | ISUPPORT `draft/ACCOUNTREQUIRED` |
| `timeout` | 15s | Si les services ne répondent pas |

La cap n’est **pas** listée en CAP LS 301 (draft). Le client **doit** `CAP REQ` avant `REGISTER`/`VERIFY`.

Si une connect class a `requireaccount`, le module envoie `FAIL * ACCOUNT_REQUIRED` (en plus du refus de classe de `m_account`).

## Protocole services (ENCAP ACCREG)

Mot de passe en **Base64** (table standard, padding `=`) pour ne pas casser la ligne S2S.

### ircd → services

```
ENCAP <services> ACCREG <uid> REGISTER <account> <email> <ip> <host> <S|P> <certfp|*> :<password-b64>
ENCAP <services> ACCREG <uid> VERIFY <account> :<code>
ENCAP <services> ACCREG <uid> ABORT :*
```

`S` = connexion TLS, `P` = plaintext. `email` peut être `*`.

### services → ircd

```
ENCAP * ACCREG <uid> SUCCESS <account> :<message>
ENCAP * ACCREG <uid> VERIFICATION_REQUIRED <account> :<message>
ENCAP * ACCREG <uid> FAIL REGISTER ACCOUNT_EXISTS <account> :<message>
ENCAP * ACCREG <uid> FAIL VERIFY INVALID_CODE <account> :<message>
```

Codes FAIL côté services (spec) : `ACCOUNT_EXISTS`, `BAD_ACCOUNT_NAME`, `WEAK_PASSWORD`, `UNACCEPTABLE_PASSWORD`, `INVALID_EMAIL`, `UNACCEPTABLE_EMAIL`, `INVALID_CODE`, `TEMPORARILY_UNAVAILABLE`.

**Sur SUCCESS**, les services **doivent** aussi identifier l’utilisateur (METADATA `accountname` / équivalent SVSLOGIN). Sinon le client reçoit `REGISTER SUCCESS` sans numeric 900 / account-notify.

## Dépendances

- `cap`
- `account` (login après SUCCESS)
- Services qui implémentent `ACCREG` (pas encore dans Anope/Atheme stock)

Un squelette Anope 2 est dans `anope/ns_ircv3_register.cpp`.
