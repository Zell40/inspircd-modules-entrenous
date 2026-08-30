# inspircd-modules-entrenous

Modules **InspIRCd 4** (et compagnons services) pour le réseau Entre Nous.

Ce dépôt n’est pas un fork d’InspIRCd : chaque module se copie dans `src/modules/` de ton arbre InspIRCd 4 (fichier `m_….cpp` ou dossier `m_…/`), puis tu recompiles.

## Modules

| Module | Rôle |
|---|---|
| [`inspircd4/m_account_registration.cpp`](inspircd4/m_account_registration.cpp) | Cap IRCv3 `draft/account-registration` (`REGISTER` / `VERIFY`) |
| [`inspircd4/m_ircv3_webpush/`](inspircd4/m_ircv3_webpush/) | Caps IRCv3 `soju.im/webpush` / `draft/webpush` (`WEBPUSH`) |
| [`inspircd4/m_ircv3_metadata.cpp`](inspircd4/m_ircv3_metadata.cpp) | Caps IRCv3 `draft/metadata-2` / `draft/metadata-3` (`METADATA`) |
| [`anope/ns_ircv3_register.cpp`](anope/ns_ircv3_register.cpp) | Squelette Anope 2 pour `ENCAP ACCREG` (expérimental) |

Documentation détaillée : [`inspircd4/README.md`](inspircd4/README.md).

## Licence

Les modules InspIRCd qui incluent `inspircd.h` sont sous **GNU GPL v2**, comme InspIRCd.
