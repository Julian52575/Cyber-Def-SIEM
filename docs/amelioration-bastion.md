# Améliorations du bastion

## Comptes nominatifs et blocage SSH de `admin`

### Objectif

Au départ, le bastion n'avait qu'un compte partagé, `admin`. Nous avons créé un compte par membre de l'équipe, pour que chaque connexion et chaque commande `sudo` soit attribuée à une personne dans `/var/log/auth.log` (et donc dans le SIEM).

Le compte `admin` doit rester actif. Nous avons seulement bloqué ses connexions SSH.

### Ce qui a été mis en place

| Élément | Configuration |
| ------- | ------------- |
| Groupe | `blueteam` |
| Utilisateurs | `rulian`, `julian`, `eliott`, `jeremie` (membres de `blueteam`) |
| Connexion SSH | Par clé uniquement, réservée au groupe `blueteam` |
| Droits root | `sudo` pour le groupe `blueteam`, avec mot de passe |
| `admin` | Compte actif, connexion SSH refusée |
| `root` | Connexion SSH refusée |

### Commandes

#### 1. Groupe et utilisateurs

```sh
sudo groupadd blueteam

for u in rulian julian eliott jeremie; do
  sudo useradd -m -s /bin/bash -G blueteam "$u"
  sudo install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
  sudo install -m 600 -o "$u" -g "$u" /dev/null "/home/$u/.ssh/authorized_keys"
done
```

Chaque membre génère sa clé sur son poste (`ssh-keygen -t ed25519`) et transmet uniquement la partie `.pub`, ajoutée ensuite dans son fichier :

```sh
echo 'ssh-ed25519 AAAA... eliott@laptop' | sudo tee -a /home/eliott/.ssh/authorized_keys
```

Chaque membre définit ensuite son mot de passe, qui sert uniquement pour `sudo` :

```sh
sudo passwd eliott
```

#### 2. Droits sudo

```sh
echo '%blueteam ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/blueteam
sudo chmod 440 /etc/sudoers.d/blueteam
sudo visudo -c
```

#### 3. Durcissement SSH

Fichier `/etc/ssh/sshd_config.d/50-hardening.conf` :

```
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowGroups blueteam
DenyUsers admin
```

`DenyUsers` est évalué avant `AllowGroups` : `admin` reste refusé même s'il est ajouté un jour au groupe `blueteam`.

Le bastion n'utilise pas systemd (`systemctl` échoue). Pour recharger la configuration, on envoie `HUP` au processus sshd principal, ce qui ne coupe pas les sessions ouvertes :

```sh
sudo sshd -t && sudo kill -HUP "$(cat /run/sshd.pid)"
```

Ne pas utiliser `pkill -HUP sshd` : le signal partirait aussi aux processus des sessions ouvertes.

### Vérifications

Depuis un autre terminal, en gardant une session ouverte sur le bastion :

- `ssh <membre>@<ip-du-bastion>` puis `sudo -v` fonctionnent pour chacun des 4 membres.
- `ssh admin@<ip-du-bastion>` est refusé.
- L'interface « Hospital interfaces » (Python runner, etc.) fonctionne toujours.

### Points ouverts

- `/home/admin/.ssh/authorized_keys` contient une clé `lp1@starlite`, d'origine inconnue. À identifier (clé des organisateurs ?) avant toute modification.
