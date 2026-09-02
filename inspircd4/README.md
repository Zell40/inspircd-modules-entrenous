# Modules InspIRCd 4 (Entre Nous)

Copier les modules dans `src/modules/` de ton arbre [InspIRCd 4](https://github.com/inspircd/inspircd), puis recompiler (`make`).

Un module peut être **un seul** `m_….cpp`, ou un **dossier** `m_…/` (plusieurs `.cpp` / `.h` à l’intérieur — InspIRCd les compile comme un seul module, comme `m_spanningtree`).

---

# m_account_registration

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

---

# m_ircv3_metadata

Module extra pour [draft/metadata-2](https://ircv3.net/specs/extensions/metadata.html) et [draft/metadata-3](https://github.com/ircv3/ircv3-specifications/pull/613) : commandes `METADATA` (`GET` / `SET` / `LIST` / `CLEAR` / `SUB` / `UNSUB` / `SUBS` / `SYNC`).

Compatible avec **Orbit**, qui négocie uniquement `draft/metadata-2` et attend :
- `METADATA * SUB avatar bio pronouns timezone url`
- `METADATA <nick> GET …`
- pushes live en verbe `METADATA <target> <key> <visibility> [:<value>]` (ou numeric `761`)
- préférences buffer **par utilisateur** : `soju.im/muted`, `soju.im/pinned`, `soju.im/blocked` (`0`/`1`) sur un salon ou un nick (sourdine Web Push, etc.)

Les clients `draft/metadata-3` reçoivent les pushes en numeric `761` / `766` (comportement -3).

Stockage local (fichier data), clé = **compte** SASL si connecté, sinon nick. Pas de sync S2S pour l’instant (réseau mono-serveur). Les clés `soju.im/*` buffer ne sont **pas** partagées entre membres du salon (contrairement au metadata canal classique).

## Installation

1. Copier `m_ircv3_metadata.cpp` **et** le dossier `m_ircv3_webpush/` (au moins pour `ircv3_metadata.h`) dans `src/modules/`. Rien à ajouter dans `include/modules/`.
2. Recompiler (`make`).
3. Charger **après** `cap` (et `account` / `monitor` recommandés) :

```xml
<module name="cap">
<module name="account">
<module name="ircv3">
<module name="monitor">
<module name="ircv3_metadata">

<ircv3metadata
    maxsubs="32"
    maxkeys="16"
    maxvaluebytes="500"
    requireaccount="yes"
    allowkeys="avatar bio pronouns timezone url"
    persistfile="ircv3-metadata.db"
    synclimit="200"
    beforeconnect="no"
    saveperiod="30s">
```

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `maxsubs` | 32 | Plafond de clés en `SUB` |
| `maxkeys` | 16 | Plafond de clés stockées par utilisateur/canal |
| `maxvaluebytes` | 500 | Taille max d’une valeur |
| `requireaccount` | yes | `SET` exige un compte SASL |
| `allowkeys` | `avatar bio pronouns timezone url` | Liste blanche profil (vide = toute clé valide). Les clés buffer `soju.im/muted`, `soju.im/pinned`, `soju.im/blocked` sont **toujours** autorisées |
| `persistfile` | `ircv3-metadata.db` | Persistance profil + préférences buffer |
| `synclimit` | 200 | Au-delà, `JOIN` envoie `774` au lieu du burst |
| `beforeconnect` | no | Autoriser `METADATA` avant le 001 |
| `saveperiod` | 30s | Fréquence d’écriture du fichier |

Les caps ne sont **pas** listées en CAP LS 301. Le client **doit** `CAP REQ draft/metadata-2` (Orbit) ou `draft/metadata-3`.

Exemple Orbit / client :
```
METADATA * SET avatar :https://cdn.example/me.png
METADATA * SET bio :Bonjour
METADATA Alice GET avatar bio pronouns timezone url
METADATA #salon SET soju.im/muted 1
METADATA #salon SET soju.im/muted
METADATA #salon GET soju.im/muted
```

API C++ (`m_ircv3_webpush/ircv3_metadata.h`) : `IRCv3Metadata::API` expose `IsMuted` / `IsMutedOwner` / `IsBlocked` pour webpush (et d’éventuels autres modules sous `src/modules/`).
## Dépendances

- `cap` (obligatoire pour annoncer les caps)
- `account` si `requireaccount="yes"`
- `monitor` optionnel (pousse aussi vers les cibles MONITOR)

---

# m_ircv3_chathistory

Module extra pour [draft/chathistory](https://ircv3.net/specs/extensions/chathistory) : commande `CHATHISTORY` (`LATEST` / `BEFORE` / `AFTER` / `AROUND` / `BETWEEN`), plus la cap **`draft/event-playback`** (JOIN/PART/QUIT/KICK/NICK/TOPIC/MODE dans le batch).

Compatible avec **Orbit** :
- `CHATHISTORY LATEST #chan * 50` au JOIN
- `CHATHISTORY BEFORE #chan timestamp=… 50` au scroll
- réponses dans un **batch** type `chathistory` (nécessite `ircv3_batch`) avec tags `time` / `msgid`
- événements historiques si Orbit a négocié `draft/event-playback`

Ce n’est **pas** le mode `+H` (`m_chanhistory`). Les deux peuvent coexister ; Orbit déduplique. La spec recommande de ne pas rejouer l’historique auto si le client a `draft/chathistory` — le `+H` officiel le fait encore.

Stockage **mémoire** (perdu au restart), ring buffer par canal (+ MP optionnels). Pas de `TARGETS` pour l’instant.

## Installation

1. Copier `m_ircv3_chathistory.cpp` dans `src/modules/`.
2. Recompiler (`make`).
3. Charger **après** `cap`, `ircv3_batch`, `ircv3_servertime` (et `ircv3_msgid` recommandé) :

```xml
<module name="cap">
<module name="ircv3">
<module name="ircv3_batch">
<module name="ircv3_servertime">
<module name="ircv3_msgid">
<module name="ircv3_chathistory">

<ircv3chathistory
    maxlines="500"
    maxduration="7d"
    maxquery="50"
    savepms="yes"
    savebots="yes"
    saveevents="yes"
    saveusermodes="yes"
    clearminrank="op"
    allowselfpmclear="yes">
```

**Important — déploiement du binaire :** `/rehash` relit la config mais **ne recharge pas** le fichier `.so` du module. Après `make install`, il faut **redémarrer InspIRCd** ou, en IRCop : `/RELOADMODULE ircv3_chathistory`. Sans ça, une ancienne version du module tourne encore (pas de log `saveusermodes`, filtre ignoré).

Les tags InspIRCd sont **plats** (pas de balises XML imbriquées) : `<module name="…">` et `<ircv3chathistory …>` sont deux lignes distinctes, pas un bloc `<module>…</module>`.

**Vérification au démarrage / reload** (dans `logs/inspircd.log`) :

```
Entre Nous IRCv3 chathistory loaded (saveusermodes supported)
ircv3chathistory: saveusermodes=no
```

Si la première ligne est absente, le mauvais module (ou une vieille build) est chargé. Si la seconde affiche `yes` alors que la config dit `no`, le tag `<ircv3chathistory>` n’est pas lu (emplacement ou syntaxe).

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `maxlines` | 500 | Messages/événements gardés par canal / conversation MP |
| `maxduration` | 7d | Âge max des entrées stockées |
| `maxquery` | 50 | Plafond `limit` (ISUPPORT `CHATHISTORY`) |
| `savepms` | yes | Historique des messages privés |
| `savebots` | yes | Enregistrer les messages des umode `+B` |
| `saveevents` | yes | Stocker JOIN/PART/… pour `draft/event-playback` |
| `saveusermodes` | yes | Stocker les MODE préfixe utilisateur (+o, +v, +h, …) dans l’historique ; `no` les exclut du stockage, du rejeu, et purge ceux déjà en mémoire au rehash/reload. **Ne masque pas** les MODE **en direct** (Orbit : paramètre « Masquer les changements de mode ») |
| `clearminrank` | `op` | Rang canal minimum pour `CHATHISTORY CLEAR #chan` (`voice` / `halfop` / `op` / `admin` / `founder`, lettre, ou rang numérique) |
| `allowselfpmclear` | yes | Un utilisateur peut `CLEAR` l’historique de **sa** conversation privée avec un nick |

## Purge manuelle : `CHATHISTORY CLEAR`

```
CHATHISTORY CLEAR #canal
CHATHISTORY CLEAR AutreNick
```

Ne nécessite **pas** la CAP `draft/chathistory` (utile pour les ops / IRCops hors Orbit).

| Qui | Canal | MP |
|---|---|---|
| Staff canal | Rang ≥ `clearminrank` (défaut `@`) | — |
| Participant | — | Conversation avec ce nick si `allowselfpmclear` (buffer partagé : les deux côtés perdent l’historique serveur) |
| IRCop | Priv `channels/clear-chathistory` (sans être op / membre) | Priv `users/clear-chathistory` : efface **toutes** les conversations MP impliquant ce nick (online ou offline) |

Pistes de limitation IRCop (à coller dans `opers.conf` via `privs=` — voir `opers-entrenous.example.conf`) :

- **`channels/clear-chathistory`** : NetAdmin + GlobalOp ; pas les classes « helpdesk » / local-only.
- **`users/clear-chathistory`** : plus sensible (vie privée) → NetAdmin / senior staff seulement.
- Combiner avec les classes InspIRCd existantes (`servers/`, `users/auspex`, etc.) : un op qui a déjà `users/auspex` n’obtient pas automatiquement le clear ; les deux privs sont **explicitement** à ajouter.
- Audit : chaque CLEAR émet un snomask `a` (server notices).

ISUPPORT : `CHATHISTORY=<maxquery>`, `MSGREFTYPES=timestamp,msgid`.

Sans `draft/event-playback` négocié, le batch ne contient que PRIVMSG/NOTICE (spec).

## Dépendances

- `cap`
- `ircv3_batch` (**obligatoire** pour Orbit)
- `ircv3_servertime` (tag `time`)
- `ircv3_msgid` recommandé (tag `msgid` pour dédup / react)

## Help / opers

- Topics `/HELP` : [`help-entrenous.example.conf`](help-entrenous.example.conf) — à `include` depuis ton fichier help réseau.
- Privs oper : [`opers-entrenous.example.conf`](opers-entrenous.example.conf)

---

# m_ircv3_read_marker

Module extra pour [draft/read-marker](https://ircv3.net/specs/extensions/read-marker) : commande `MARKREAD`, sync du « déjà lu » entre sessions du même compte.

Compatible avec **Orbit** (`MARKREAD #chan timestamp=<ISO>`).

- Au JOIN d’un canal : envoie le marqueur courant (`timestamp=…` ou `*`)
- Au SET : n’accepte que des timestamps **plus récents** ; diffuse aux autres clients locaux du même compte
- GET : `MARKREAD <target>` sans timestamp

## Installation

```xml
<module name="cap">
<module name="account">
<module name="ircv3_read_marker">

<ircv3readmarker
    requireaccount="yes"
    persistfile="ircv3-readmarker.db"
    saveperiod="30s">
```

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `requireaccount` | yes | Exiger un login pour `MARKREAD` SET ; la cap n’est listée qu’aux utilisateurs identifiés (CAP NEW après SASL si `cap-notify`) |
| `persistfile` | `ircv3-readmarker.db` | Persistance disque |
| `saveperiod` | 30s | Fréquence d’écriture |

## Dépendances

- `cap`
- `account` si `requireaccount="yes"`

---

# m_ircv3_multiline

Module extra pour [draft/multiline](https://ircv3.net/specs/extensions/multiline) : envoi client de messages multi-lignes dans un batch `draft/multiline`.

Compatible avec **Orbit** : collage multi-ligne → `BATCH +… draft/multiline <cible>`, lignes `PRIVMSG` taguées `@batch=…` (+ `draft/multiline-concat` si coupure 512), `BATCH -…`. Nécessite aussi la cap `batch` (`ircv3_batch`).

## Installation

```xml
<module name="cap">
<module name="ircv3">
<module name="ircv3_batch">
<module name="ircv3_servertime">
<module name="ircv3_msgid">
<module name="ircv3_multiline">

<ircv3multiline maxlines="20" maxbytes="40000" batchtimeout="30s" maxbatchesperminute="10">
```

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `maxlines` | 20 | Plafond de lignes `PRIVMSG`/`NOTICE` par batch (CAP `max-lines`) |
| `maxbytes` | 40000 | Taille totale du texte concaténé (CAP `max-bytes`, LF inclus) |
| `batchtimeout` | 30s | Ferme un batch ouvert sans `BATCH -` (timer 5 s) |
| `maxbatchesperminute` | 10 | Plafond de batches **envoyés** par utilisateur et par minute (`0` = désactivé) |

Annonce `draft/multiline=max-bytes=…,max-lines=…` en CAP LS.

Les clients sans `draft/multiline` reçoivent un **fallback** : plusieurs `PRIVMSG` séparés (lignes vides omises), tags `msgid`/`account` sur la première ligne.

Avec `echo-message`, l’expéditeur reçoit le batch en écho (tag `inspircd.org/echo`).

Erreurs : `FAIL BATCH MULTILINE_*` (standard-replies).

## Dépendances

- `cap`
- `ircv3_batch` (**obligatoire** pour Orbit)
- `ircv3_servertime` recommandé (`time` sur le `BATCH` d’ouverture)
- `message-tags` / `ircv3_ctctags` pour `+draft/channel-context` (MP contextualisés Orbit)

---

# m_ircv3_webpush

Module extra pour l’extension IRCv3 [Web Push](https://github.com/ircv3/ircv3-specifications/pull/471) (vendored `soju.im/webpush`, aussi annoncé comme `draft/webpush`). Compatible avec **Orbit** (navigateur) et des clients mobiles type Goguma.

Le module :

- annonce les caps `soju.im/webpush` et `draft/webpush`, plus le token ISUPPORT `VAPID` (clé publique P-256, RFC 8292) ;
- implémente `WEBPUSH REGISTER <endpoint> <keys>` et `WEBPUSH UNREGISTER <endpoint>` ;
- chiffre le payload en **aes128gcm** (RFC 8291) et POSTe en HTTPS vers l’endpoint push ;
- refuse les URL non-`https` et les adresses privées / loopback (protection SSRF, comme soju/Ergo) ;
- envoie le payload comme **une ligne IRC** (tags `time`, `msgid`, `account` si présents) pour que le client puisse réinjecter l’événement.

InspIRCd n’est pas un bouncer always-on : un client **connecté et non-away** ne reçoit pas de Web Push (il a déjà le trafic IRC). Les push partent surtout si le destinataire est **away** (`pushaway`), ou via `pushoffline` pour les MP vers un nick hors ligne, ou si `pushalways=yes`.

## Installation

Dépendance de compilation : **OpenSSL** (`libssl-dev` / `openssl-dev`). Les certificats CA système doivent être installés pour valider le TLS des endpoints (FCM, Mozilla autopush, etc.).

1. Copier le dossier `m_ircv3_webpush/` entier dans `src/modules/` (comme `m_spanningtree`). L’API metadata (`ircv3_metadata.h`) est **dans ce dossier** — pas dans `include/modules/`.
2. Recompiler (`make`). Le `./configure` d’InspIRCd lit les `$CompilerFlags` / `$LinkerFlags` de `main.cpp`.
3. Charger **après** `cap`, `account` (si `requireaccount="yes"`), et de préférence **`ircv3_metadata`** (sourdine salon → pas de push) :

```xml
<module name="cap">
<module name="account">
<module name="ircv3">
<module name="ircv3_servertime">
<module name="ircv3_metadata">
<module name="ircv3_webpush">

<webpush
    vapidfile="webpush-vapid.pem"
    persistfile="webpush.db"
    contact="mailto:admin@example.net"
    requireaccount="yes"
    maxsubscriptions="5"
    ttl="1d"
    expiration="30d"
    pushaway="yes"
    pushoffline="yes"
    pushalways="no"
    pushnotices="yes"
    noticecooldown="10s"
    testonregister="yes"
    httptimeout="15s"
    maxperminute="30"
    saveperiod="30s">
```

Au premier démarrage, une paire de clés VAPID est générée dans `vapidfile` (répertoire data d’InspIRCd). **Garde ce fichier** : changer la clé publique casse les abonnements existants.

## Configuration

| Attribut | Défaut | Effet |
|---|---|---|
| `vapidfile` | `webpush-vapid.pem` | Clé privée VAPID (PEM) |
| `persistfile` | `webpush.db` | Abonnements persistés (redémarrage) |
| `contact` | `mailto:webpush@<servername>` | Claim `sub` JWT VAPID (`mailto:` ou `https:`) |
| `requireaccount` | yes | `WEBPUSH` exige un compte SASL / services |
| `maxsubscriptions` | 5 | Plafond d’endpoints par compte |
| `ttl` | 86400 | Header HTTP `TTL` (RFC 8030) |
| `expiration` | 30d | Oublier un abonnement non renouvelé |
| `pushaway` | yes | Push si le destinataire est away |
| `pushoffline` | yes | Push des MP vers le dernier nick d’un compte offline |
| `pushalways` | no | Push même si le destinataire est connecté et non-away |
| `pushnotices` | yes | Autoriser les push pour les `NOTICE` (sinon PRIVMSG/INVITE seulement) |
| `noticecooldown` | 10s | Anti-rafale : au plus un push NOTICE par compte dans cette fenêtre (bots au JOIN, etc.) |
| `testonregister` | yes | Envoie `PING webpush` pour valider l’endpoint |
| `httptimeout` | 15s | Timeout du POST HTTPS |
| `maxperminute` | 30 | Rate-limit de pushes par compte |
| `saveperiod` | 30s | Fréquence d’écriture de `persistfile` |

Les caps ne sont **pas** listées en CAP LS 301. Le client **doit** `CAP REQ soju.im/webpush` (ou `draft/webpush`) avant `WEBPUSH`.

`keys` au format message-tags : `p256dh=<b64url>;auth=<b64url>`.

## Commandes

```
WEBPUSH LIST
WEBPUSH REGISTER <endpoint> p256dh=<b64url>;auth=<b64url>
WEBPUSH UNREGISTER <endpoint|device-id>
```

- Abonnements stockés par **compte** (`a:<compte>`) si `requireaccount=yes`, sinon par nick (`n:<nick>`).
- `LIST` renvoie une ligne `WEBPUSH DEVICE <id> <host> <nick> <updated> <last_success> <online 0|1> <shared 0|1>` par appareil, puis `WEBPUSH END *`. `<id>` est un identifiant stable 16 hex (SHA-256 tronqué de l’endpoint) ; `UNREGISTER` accepte l’endpoint https complet **ou** cet id. `<shared>` vaut `1` si le même endpoint est enregistré pour un **autre** compte (sans révéler lequel).
- `REGISTER` associe l’endpoint à la session courante (UUID) pour détecter si le « registrar » est encore en ligne.
- Réponses serveur : `WEBPUSH REGISTER|UNREGISTER <endpoint>` (echo de confirmation).
- Erreurs typiques : `NO_CAPABILITY`, `FORBIDDEN` (pas de compte), `INVALID_PARAMS` (URL non-https / clés invalides), `TOO_MANY` (plafond `maxsubscriptions`).

## Quand un push part

Un push n’est envoyé que si le destinataire a au moins un abonnement actif et que `ShouldNotifyUser` accepte (voir ci-dessous). Les POST partent d’un **thread dédié** pour ne pas bloquer l’ircd. Un `410`/`404` HTTP retire l’abonnement expiré.

| Événement | Urgence HTTP | Conditions |
|---|---|---|
| **PRIVMSG** privé | `high` | Destinataire local ; pas mute/block ; session à notifier |
| **NOTICE** privé | `high` | Idem + `pushnotices=yes` + anti-rafale `noticecooldown` |
| **Highlight** canal (nick du membre, frontières de mot) | `normal` | Membre local du canal ; pas `soju.im/muted` ; session à notifier |
| **INVITE** | `high` | Invité local ; canal non en sourdine ; session à notifier |
| **MP offline** (`pushoffline`) | `high` | Nick inexistant mais dernier nick connu d’un compte abonné |

**Multi-pseudos / même compte :** les abonnements sont par compte, mais :

1. une session **connectée et non-away** ne déclenche **pas** de Web Push (elle voit déjà le IRC) — donc Jessie qui JOIN et reçoit 5 NOTICE bots **n’envoie plus** ces notices sur le téléphone de Zell hors ligne ;
2. seuls les endpoints dont la session « registrar » est **hors ligne** reçoivent le POST (pas l’appareil encore connecté).

Les NOTICE de salon **sans** highlight de nick ne génèrent pas de push. Les CTCP (`ACTION` exceptée) non plus.

**`ShouldNotifyUser`** (simplifié) :

- `pushalways=yes` → toujours notifier ;
- sinon, si le destinataire local est **away** et `pushaway=yes` → notifier (appareils idle seulement) ;
- sinon (connecté, présent) → **pas** de push.

**Anti-rafale NOTICE :** après un push NOTICE pour un compte, les suivants sont ignorés pendant `noticecooldown` (défaut 10 s). Utile contre les bots qui envoient 4–5 notices au JOIN. Mettre `pushnotices="no"` pour couper tous les push NOTICE.

## Sourdine et blocage (`ircv3_metadata`)

Avec **`ircv3_metadata`** chargé, le module interroge l’API `ircv3metadataapi` :

| Clé metadata | Effet sur Web Push |
|---|---|
| `soju.im/muted=1` sur `#salon` ou nick | Aucun push lié à ce salon / cette conversation MP |
| `soju.im/blocked=1` sur un nick | Aucun push **depuis** ce nick (MP et highlights) |

Stockage **par compte** (pas partagé entre membres du salon). Sans `ircv3_metadata`, le filtrage mute/block est ignoré.

**Orbit** synchronise la sourdine salon avec le serveur :

- sourdine dans l’UI → `METADATA #chan SET soju.im/muted 1` ;
- restauration au JOIN → `METADATA #chan GET soju.im/muted` ;
- le toggle Web Push (paramètres Notifications) enregistre l’endpoint navigateur via `WEBPUSH REGISTER` quand ISUPPORT expose `VAPID` et qu’un compte NickServ est actif.

## Intégration Orbit

1. Le serveur annonce `VAPID=<clé publique b64url>` en ISUPPORT.
2. Orbit négocie `draft/webpush` (liste dans `caps.ts`).
3. Après login compte, l’utilisateur active les notifications push dans **Paramètres → Notifications**.
4. Le navigateur crée une subscription `PushManager` ; Orbit envoie `WEBPUSH REGISTER` avec l’endpoint et les clés.
5. Les pushes reçus sont des lignes IRC (`:nick!… PRIVMSG …`) que le client peut afficher comme notification desktop.

Prérequis côté navigateur : HTTPS, permission `Notification`, support `PushManager` (pas en iOS Safari standalone classique).

## Test crypto (RFC 8291)

Hors InspIRCd, les vecteurs de l’annexe A de RFC 8291 :

```
cd inspircd4
g++ -O2 -o test_webpush_crypto test_webpush_crypto.cpp -lcrypto
./test_webpush_crypto
```

## Dépendances

- `cap` (obligatoire pour annoncer les caps)
- `account` si `requireaccount="yes"` (recommandé pour Orbit)
- `ircv3_metadata` (recommandé : sourdine salon / blocage nick)
- `ircv3_servertime` (recommandé : tag `time` sur le payload push)
- OpenSSL (libcrypto + libssl)
- Client Web Push : **Orbit** (web) ou Goguma (mobile)

