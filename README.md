# 🚀 AD Replication Inspector


**Ayi NEDJIMI Consultants - WinToolsSuite**

## 📋 Description

Outil de monitoring de la topologie de réplication Active Directory avec analyse de cohérence USN, détection de latence et erreurs de réplication.


## ✨ Fonctionnalités

- **Scan topologie AD**: Query LDAP CN=Sites,CN=Configuration pour lister sites et DCs
- **Énumération DCs**: Lecture CN=Servers sous chaque site
- **Lecture USN**: Extraction highestCommittedUSN via rootDSE pour chaque DC
- **Comparaison USN**: Détection des délais de réplication entre DCs
- **Erreurs réplication**: Query Event Log Directory Service (Event IDs 1311, 1388, 2042)
- **Calcul latence**: Approximation basée sur différence USN
- **Export CSV UTF-8 BOM**: Sauvegarde du rapport de réplication


## 🔌 APIs Utilisées

- `activeds.lib`: LDAP/ADSI pour query sites, serveurs, rootDSE
- `netapi32.lib`: DsGetDcName pour informations domaine
- `wevtapi.lib`: EvtQuery pour lecture erreurs réplication
- `comctl32.lib`: ListView, StatusBar


## Compilation

```batch
go.bat
```

Ou manuellement:
```batch
cl.exe /EHsc /std:c++17 ADReplicationInspector.cpp activeds.lib adsiid.lib netapi32.lib wevtapi.lib comctl32.lib ole32.lib oleaut32.lib user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS
```


## 🚀 Utilisation

1. **Scanner topologie**: Énumère sites et DCs, lit les USN
2. **Vérifier USN**: Analyse cohérence et différences USN entre DCs
3. **Tester réplication**: Vérifie erreurs dans logs et suggère commandes
4. **Exporter**: Sauvegarde en CSV UTF-8


## Event IDs Réplication

- **1311**: KCC (Knowledge Consistency Checker) a détecté des problèmes
- **1388**: Échec de réplication avec un DC source
- **2042**: Réplication échouée pendant trop longtemps (alerte critique)


## Interprétation Latence

- **Synchronisé**: Différence USN < 1000 (excellent)
- **< 10 min**: Différence USN < 10000 (normal)
- **> 10 min**: Différence USN > 10000 (vérifier connectivité)


## 📌 Prérequis

- Machine jointe à domaine Active Directory
- Privilèges administrateur ou lecture AD
- Windows Server 2008+ ou Windows 7+ avec RSAT


## Commandes Complémentaires

```batch
repadmin /showrepl          # Statut réplication détaillé
repadmin /replsummary       # Résumé global
dcdiag /test:replications   # Diagnostic complet
repadmin /syncall /AdeP     # Force synchronisation
```


## Logging

Logs sauvegardés dans: `%TEMP%\ADReplicationInspector.log`


## Structure

- **ADSI/LDAP**: Énumération sites et serveurs via IADsContainer
- **rootDSE**: Lecture highestCommittedUSN pour chaque DC
- **Threading**: Scan asynchrone via std::thread
- **UI Française**: Interface complète en français


## 💬 Notes

- L'USN (Update Sequence Number) reflète l'état de réplication
- Une différence USN élevée indique un retard de réplication
- Les erreurs critiques (2042) nécessitent une intervention immédiate

- --

**WinToolsSuite** - Sécurité et Administration Windows
Ayi NEDJIMI Consultants © 2025


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>