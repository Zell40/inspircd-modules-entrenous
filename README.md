# inspircd-modules-entrenous

Modules **InspIRCd 4** (et compagnons services) pour le réseau Entre Nous.

Ce dépôt n’est pas un fork d’InspIRCd : chaque module se copie dans `src/modules/` de ton arbre InspIRCd 4, puis tu recompiles.

## Modules

| Module | Rôle |
|---|---|
| [`inspircd4/m_account_registration.cpp`](inspircd4/m_account_registration.cpp) | Cap IRCv3 `draft/account-registration` (`REGISTER` / `VERIFY`) |
| [`anope/ns_ircv3_register.cpp`](anope/ns_ircv3_register.cpp) | Squelette Anope 2 pour `ENCAP ACCREG` (expérimental) |

Documentation détaillée : [`inspircd4/README.md`](inspircd4/README.md).

## Licence

Les modules InspIRCd qui incluent `inspircd.h` sont sous **GNU GPL v2**, comme InspIRCd.
