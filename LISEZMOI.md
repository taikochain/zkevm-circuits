# Circuits pour zkEVM

[![Vérifications CI](https://github.com/privacy-scaling-explorations/zkevm-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/privacy-scaling-explorations/zkevm-circuits/actions/workflows/ci.yml)

Consultez la [spécification en cours](https://github.com/privacy-scaling-explorations/zkevm-specs) pour comprendre son fonctionnement.

## Pour commencer

Pour exécuter les mêmes tests que ceux de CI, veuillez utiliser : `make test-all`.

## Exécution des benchmarks

Il existe actuellement plusieurs benchmarks à exécuter dans l'espace de travail concernant les circuits.
Tous utilisent la variable d'environnement `DEGREE` pour spécifier le degré du paramètre `K` que vous souhaitez utiliser pour votre circuit dans le processus de benchmark.
-   Bancs d'essai de prouveur de circuit Keccak. -> `DEGREE=16 make packed_multi_keccak_bench`
-   Bancs d'essai de prouveur de circuit EVM. -> `DEGREE=18 make evm_bench`.
-   Bancs d'essai de prouveur de circuit d'état. -> `DEGREE=18 make state_bench`

Vous pouvez également exécuter tous les benchmarks en exécutant : `make circuit_benches DEGREE=18`.

## Résultats des benchmarks GH Actions

Les résultats des benchmarks de circuits sont accessibles ici : https://grafana.zkevm-testnet.org/d/vofy8DAVz/circuit-benchmarks?orgId=1

- Le panneau des `circuit_benchmarks` affiche :
    - le résultat global du test
    - les minuteries et les statistiques système
    - l'URL pour télécharger les fichiers journaux du prouveur et les statistiques système
    - un élément `sysstats_url` cliquable qui charge les profils d'utilisation de la mémoire et du processeur pour le test donné
