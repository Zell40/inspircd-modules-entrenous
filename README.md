# inspircd-modules-entrenous

Modules **InspIRCd 4** (et compagnons services) pour le réseau Entre Nous.

Ce dépôt n’est pas un fork d’InspIRCd : chaque module se copie dans `src/modules/` de ton arbre InspIRCd 4 (fichier `m_….cpp` ou dossier `m_…/`), puis tu recompiles.

## Modules

| Module | Rôle |
|---|---|
| [`inspircd4/m_account_registration.cpp`](inspircd4/m_account_registration.cpp) | Cap IRCv3 `draft/account-registration` (`REGISTER` / `VERIFY`) |
| [`inspircd4/m_ircv3_webpush/`](inspircd4/m_ircv3_webpush/) | Caps IRCv3 `soju.im/webpush` / `draft/webpush` (`WEBPUSH`) |
| [`inspircd4/m_ircv3_metadata.cpp`](inspircd4/m_ircv3_metadata.cpp) | Caps IRCv3 `draft/metadata-2` / `draft/metadata-3` (`METADATA`, dont `soju.im/muted`) |
| [`inspircd4/m_ircv3_webpush/ircv3_metadata.h`](inspircd4/m_ircv3_webpush/ircv3_metadata.h) | API C++ `IRCv3Metadata::API` (dans le dossier webpush, pas dans `include/modules/`) |
| [`inspircd4/m_ircv3_chathistory.cpp`](inspircd4/m_ircv3_chathistory.cpp) | Caps IRCv3 `draft/chathistory` + `draft/event-playback` (`CHATHISTORY`, dont `CLEAR`) |
| [`inspircd4/m_ircv3_read_marker.cpp`](inspircd4/m_ircv3_read_marker.cpp) | Cap IRCv3 `draft/read-marker` (`MARKREAD`) |
| [`inspircd4/m_ircv3_multiline.cpp`](inspircd4/m_ircv3_multiline.cpp) | Cap IRCv3 `draft/multiline` (messages multi-lignes en batch) |
| [`inspircd4/m_securitygroups.cpp`](inspircd4/m_securitygroups.cpp) | Groupes de sécurité style Unreal (`SECURITYGROUPS`, extban `~g`, WHOIS) |
| [`anope/ns_ircv3_register.cpp`](anope/ns_ircv3_register.cpp) | Squelette Anope 2 pour `ENCAP ACCREG` (expérimental) |

Aide `/HELP` : [`inspircd4/help-entrenous.example.conf`](inspircd4/help-entrenous.example.conf)  
Privs oper (clear historique) : [`inspircd4/opers-entrenous.example.conf`](inspircd4/opers-entrenous.example.conf)

Documentation détaillée : [`inspircd4/README.md`](inspircd4/README.md).

## Licence

Les modules InspIRCd qui incluent `inspircd.h` sont sous **GNU GPL v2**, comme InspIRCd.
