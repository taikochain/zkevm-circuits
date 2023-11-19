# Lignes directrices de contribution pour zkEVM

Merci d'investir votre temps pour contribuer à notre projet !

# Comment contribuer

Commencez par jeter un œil à nos [spécifications](https://github.com/privacy-scaling-explorations/zkevm-specs), nos [vidéos d'audit](https://www.youtube.com/watch?v=HhHTho2QZa4) et notre [documentation zkEVM](https://github.com/privacy-scaling-explorations/zkevm-docs). Il est très important que vous compreniez globalement le fonctionnement de l'architecture ZK-EVM et de tous ses composants.

## Meilleures pratiques de codage

### Création de PR (Pull Requests)

1. Forkzkevm ou le dépôt specs.
2. Rédigez un document de spécification simple en markdown sur la PR et envoyez-le au dépôt `zkevm-specs`.
    - ******************REMARQUE :****************** Si la PR modifie le comportement du circuit, il est recommandé de refléter les modifications en Python de haut niveau ([ici](https://github.com/privacy-scaling-explorations/zkevm-specs/tree/master/src/zkevm_specs)) et de les soumettre avec la même PR que la spécification markdown vers le dépôt `zkevm-specs`.
3. Nous encourageons tout le monde à [ouvrir un ticket](https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/new/choose) et à attendre que cette fonctionnalité/proposition soit approuvée par les mainteneurs du dépôt avant de commencer à travailler sur une PR. Cependant, cela est obligatoire pour les PRs qui modifient de manière significative le code source ou la manière dont une procédure est effectuée (test-suite, structures cross-crate, refactoring de modules).
4. Créez une branche séparée qui hébergera tous les commits. Donnez des noms de branche courts décrivant le changement.
5. Commencez à apporter vos modifications. Assurez-vous également que les commandes suivantes passent si vous avez modifié le code :
    
    ```
    make test
    make clippy
    ```
    
6. Une fois les modifications apportées, donnez au message du commit une description suffisante du changement. Le contenu du message peut être bref, comprenant juste assez de détails pour résumer l'objectif du commit. Dans d'autres cas, des explications plus approfondies sur la manière dont le commit atteint ses objectifs conviennent mieux comme commentaires dans le code.
    - ******************REMARQUE :****************** Les commits dans une pull request doivent être organisés de manière à ce que chaque commit représente une petite étape cohérente vers l'objectif global de la pull request. La structure de la pull request doit faciliter la compréhension et le suivi de chaque changement effectué par le relecteur.
7. Envoyez la PR du circuit vers le dépôt `zkevm-circuits`. Assurez-vous de donner un titre clair et une description concise de la PR et de la zone que vous modifiez.
    - ******************REMARQUE :****************** Faites des PR atomiques. Concentrez-vous sur une seule fonctionnalité ou sujet. Ne mélangez pas différents sujets ou problèmes dans la même PR si cela peut être évité.

[CONSEIL] Il se peut que vous rencontriez des commits inutiles, tels que des conflits de fusion ou des refactorisations mineures. Dans ce cas, utilisez `git rebase -i` et [squashez](https://www.git-tower.com/learn/git/faq/git-squash) tous vos commits en un seul.

[CONSEIL] Rebasez votre branche sur la dernière version de la branche principale si votre branche de pull request est utilisée depuis longtemps.

        
        ```
        git checkout main
        git pull
        git checkout ma/branche
        git rebase main
        git push -f
        ```
        

### Soumission de problèmes (issues) de bogues

1. Si vous avez identifié un bug, veuillez créer un nouveau problème ou en discuter dans nos [forums](https://github.com/privacy-scaling-explorations/zkevm-circuits/discussions).
2. Dans la description, fournissez les éléments suivants :
    - Décrivez le bug
    - Étapes concrètes pour reproduire le bug

Consultez [ce guide](https://stackoverflow.com/help/mcve) sur la création d'un exemple minimal, complet et vérifiable.

### Soumission de problèmes (issues) de fonctionnalités

1. Si vous avez identifié une fonctionnalité, veuillez créer un nouveau problème ou en discuter dans nos forums.
2. Dans la description, fournissez les éléments suivants :
    - Décrivez la fonctionnalité que vous souhaitez
    - Contexte supplémentaire

### Ajout de tests

Si la modification proposée modifie le code, ajoute de nouvelles fonctionnalités à zkevm-circuits ou corrige une fonctionnalité existante, la pull request doit inclure un ou plusieurs tests pour garantir que zkevm-circuits ne régresse pas à l'avenir.

Types de tests inclus :

- **Tests unitaires** : Les fonctions qui ont des tâches très spécifiques doivent être testées unitairement.
- **Tests d'intégration** : Pour une fonctionnalité générale et étendue, des tests d'intégration doivent être ajoutés. La meilleure façon d'ajouter un nouveau test d'intégration est de regarder les tests existants et de suivre le style.

## Considérations générales

- Lorsqu'une PR implémente un comportement qui suit un schéma différent de la conception actuelle ou introduit une nouvelle conception, veuillez vous assurer d'expliquer la logique derrière cela. Dans de tels cas, il est toujours préférable qu'il y ait un problème où ce schéma/nouvelle conception a été discuté et un accord a été trouvé à ce sujet.
- Nous exigeons au moins 2 approbations de relecture pour chaque PR, sauf dans les cas où la PR est considérée comme mineure, où une approbation de relecture suffit. Il appartient aux mainteneurs de décider s'il faut plus d'une relecture.
- Évitez de demander des relectures d'une PR dans `zkevm-circuits` lorsque l'implémentation suit une spécification qui n'est pas encore dans `master` à `zkevm-specs`. Dans ce cas, défin
