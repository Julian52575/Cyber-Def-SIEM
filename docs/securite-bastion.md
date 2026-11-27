# Sécurité du bastion

Ce document décrit tout ce qui a été mis en place le 2026-11-27 pour sécuriser le bastion : SSH, logs, fail2ban, firewall, nginx et Redis. Il complète [amelioration-bastion.md](amelioration-bastion.md) (comptes nominatifs, groupe `blueteam`) et s'appuie sur l'[inventaire des serveurs](server-inventory.md).

Chaque section donne la configuration appliquée, la raison du choix et la commande pour la vérifier.

## Contexte : un conteneur Docker sans systemd

Le bastion est un **conteneur Docker** géré par les organisateurs (`/.dockerenv` existe, le PID 1 est `bash`). Conséquences :

| Contrainte | Conséquence |
| ---------- | ----------- |
| Pas de systemd | `systemctl` échoue. Les services se lancent et se rechargent à la main (`kill -HUP`, `nginx -s reload`, `fail2ban-client start`). |
| Pas de `/dev/net/tun` | Pas de VPN noyau (WireGuard, Tailscale classique). |
| Pas de démon syslog au départ | Les logs SSH n'étaient écrits nulle part avant l'installation de rsyslog. |
| Rien ne redémarre seul | Après un redémarrage du conteneur, il faut relancer [`start-secu.sh`](#script-de-redémarrage-start-secush). |

Adresses utiles :

| Adresse | Rôle |
| ------- | ---- |
| `10.10.10.11` | Le bastion, côté réseau Docker |
| `192.168.1.100` | Le bastion, côté LAN de l'hôpital |
| `10.10.10.1` | Passerelle Docker : panel de l'école, terminal web, et proxy d'une partie du trafic web |
| `192.168.1.1` | Routeur du LAN, d'où arrive le checker des organisateurs |

L'accès SSH depuis l'extérieur passe par la passerelle de l'école : `ssh -p 221 <user>@hopitalmande.fr`, redirigé vers le port 22 du bastion. Le bastion voit la vraie IP des clients SSH.

## SSH

### Configuration du serveur

Fichier `/etc/ssh/sshd_config.d/50-hardening.conf` :

```
# Authentification
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowGroups blueteam

# Limites anti-bruteforce
MaxAuthTries 3
LoginGraceTime 20
MaxStartups 10:30:60

# Fonctions inutiles sur un bastion
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no

# Sessions inactives coupées après ~10 min
ClientAliveInterval 300
ClientAliveCountMax 2

# Logs détaillés (pour fail2ban et le SIEM)
LogLevel VERBOSE
```

| Option | Pourquoi |
| ------ | -------- |
| `AllowGroups blueteam` | Seuls julian, rulian, eliott et jeremie (le prof) peuvent se connecter. |
| `MaxAuthTries 3`, `LoginGraceTime 20` | Moins d'essais par connexion, et 20 s au lieu de 2 min pour s'authentifier. |
| `AllowAgentForwarding no` | Si le bastion est compromis, l'attaquant ne peut pas utiliser l'agent SSH des membres. Utiliser `ProxyJump` à la place. |
| `AllowTcpForwarding` (laissé à `yes`) | Nécessaire pour `ProxyJump` vers les machines internes. |
| `LogLevel VERBOSE` | Chaque connexion logue l'empreinte de la clé utilisée : on sait quelle clé s'est connectée. |

Le fichier `sshd_config` principal contient `Include /etc/ssh/sshd_config.d/*.conf` en tête : ce fichier est bien pris en compte.

Appliquer une modification, sans couper les sessions ouvertes :

```sh
sudo sshd -t && sudo kill -HUP "$(cat /run/sshd.pid)"
```

Toujours garder une session ouverte et tester une nouvelle connexion depuis un autre terminal avant de fermer la première.

Vérifier la configuration réellement appliquée :

```sh
sudo sshd -T | grep -iE 'permitrootlogin|passwordauth|maxauthtries|allowgroups|x11forwarding|allowagentforwarding|loglevel'
```

Attendu : `no`, `no`, `3`, `blueteam`, `no`, `no`, `VERBOSE`.

### Configuration côté client (chaque membre)

Dans `~/.ssh/config` sur son propre poste :

```
Host bastion
    HostName hopitalmande.fr
    Port 221
    User <prenom>
    IdentityFile ~/.ssh/<cle_du_bastion>
    IdentitiesOnly yes
```

`IdentitiesOnly yes` est indispensable : sans lui, le client essaie toutes les clés de l'agent, chaque essai compte comme un échec, et `MaxAuthTries 3` + fail2ban peuvent bannir un membre de l'équipe.

### Compte `admin`

`admin` ne fait pas partie de `blueteam` : ses connexions SSH sont refusées par `AllowGroups`. Il est gardé pour une raison précise : c'est le compte du **terminal web de secours** de l'école (port 7681, voir [Firewall](#firewall)).

| Élément | État |
| ------- | ---- |
| Clé SSH | Retirée de `/home/admin/.ssh/authorized_keys`, copie dans `/root/admin_authorized_keys.bak` |
| Shell | `/bin/bash` (nécessaire au terminal web) |
| Mot de passe | Déverrouillé (nécessaire à `sudo`) |
| Groupe `admin` | Membre : garde `sudo`, sinon la console de secours ne sert à rien |
| Groupes `sudo` et `blueteam` | Non membre |

## Logs SSH (rsyslog)

Sans démon syslog, sshd n'écrivait ses logs nulle part. fail2ban et le SIEM n'avaient donc rien à lire.

```sh
sudo apt install -y rsyslog
sudo rsyslogd
```

Les logs SSH et `sudo` arrivent dans `/var/log/auth.log`. Le message `imklog: cannot open kernel log` au démarrage est normal : Docker interdit l'accès aux logs du noyau, ce qui ne concerne pas SSH.

Si `rsyslogd` refuse de démarrer à cause d'un `/run/rsyslogd.pid` existant, vérifier que le PID indiqué ne tourne plus (`ps -p <pid>`), puis supprimer le fichier et relancer.

## fail2ban

```sh
sudo apt install -y fail2ban
```

### Jail SSH

Fichier `/etc/fail2ban/jail.local` :

```ini
[DEFAULT]
ignoreip  = 127.0.0.1/8 ::1
banaction = iptables-multiport

[sshd]
enabled  = true
mode     = aggressive
port     = 22
backend  = auto
logpath  = /var/log/auth.log
maxretry = 3
findtime = 10m
bantime  = 1h
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
```

| Option | Pourquoi |
| ------ | -------- |
| `mode = aggressive` | Avec une authentification par clé uniquement, les attaques n'apparaissent presque jamais comme `Failed password`. Ce mode détecte aussi les échecs de clé et les scanners (`banner exchange: invalid format`, `[preauth]`). |
| `port = 22` | Le 221 n'existe que sur la passerelle de l'école. Dans le conteneur, SSH écoute sur le 22, et c'est là que le ban s'applique. |
| `backend = auto` + `logpath` | Pas de systemd, donc pas de journald : fail2ban lit le fichier écrit par rsyslog. |
| `bantime.increment` | Ban progressif : 1 h, 2 h, 4 h… jusqu'à 1 semaine pour les récidivistes. |

Premier ban réel le 2026-11-27 : `172.236.228.224`, un scanner qui envoyait une poignée de main TLS sur le port SSH.

### Jail web (codes 401) : à finaliser

Bannit les IP qui accumulent les mauvais mots de passe sur Orthanc et sur l'interface web du mail (authentification HTTP Basic, réponse `401`).

Filtre `/etc/fail2ban/filter.d/nginx-401.conf` :

```ini
[Definition]
failregex = ^<HOST> - \S+ \[\] "[^"]*" 401 
ignoreregex =
```

fail2ban retire la date de la ligne avant d'appliquer le filtre : les crochets restent vides, d'où `\[\]`. Un premier essai avec `\[[^\]]+\]` ne trouvait aucune ligne.

Jail, à la fin de `/etc/fail2ban/jail.local` :

```ini
[nginx-401]
enabled  = true
port     = 80
filter   = nginx-401
backend  = auto
logpath  = /var/log/nginx/access.log
maxretry = 8
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1 192.168.1.1 10.10.10.1
```

| Option | Pourquoi |
| ------ | -------- |
| `maxretry = 8` | Un navigateur produit déjà 2 ou 3 `401` lors d'une visite normale (première requête sans mot de passe, favicon). |
| `ignoreip` | Ne jamais bannir le checker (`192.168.1.1`) ni la passerelle qui sert de proxy (`10.10.10.1`) : tous les services web passeraient au rouge. Ce `ignoreip` remplace celui de `[DEFAULT]`, d'où la reprise de `127.0.0.1`. |

Étapes restantes : tester le filtre, activer le jail, vérifier.

```sh
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-401.conf
sudo grep -c '" 401 ' /var/log/nginx/access.log   # doit être proche du "Failregex: X total"
sudo fail2ban-client reload
sudo fail2ban-client status nginx-401
```

### Démarrage et commandes utiles

```sh
sudo mkdir -p /run/fail2ban && sudo fail2ban-client start
sudo fail2ban-client status                       # liste des jails
sudo fail2ban-client status sshd                  # IP bannies
sudo fail2ban-client set sshd unbanip <ip>        # débannir
```

## Firewall

### Point de départ

Les organisateurs avaient posé des règles `ACCEPT` pour 22, 80, 443 et 6379, mais avec une politique par défaut `ACCEPT` : **tous les ports du conteneur étaient ouverts**, y compris le 7681 (terminal web) et le 8080 (SIEM), joignables par les conteneurs des autres équipes sur le réseau Docker.

### Services en écoute

D'après `sudo ss -tlnp` :

| Port | Service | Qui doit y accéder |
| ---- | ------- | ------------------ |
| 22 | sshd | Tout le monde (filtré par fail2ban) |
| 25 | nginx stream → `mail.hopital.lan:25` | Checker (service `mail`, test de port TCP) et usage normal |
| 80 | nginx, vhosts vers les services internes | Checker (5 services testés en HTTP) et visiteurs |
| 443 | rien en écoute | Règle d'origine des organisateurs, conservée |
| 6379 | nginx stream → `redis.hopital.lan:6379` | Checker uniquement (`PING`) |
| 7681 | Terminal web de l'école (processus invisible : il tourne dans un autre conteneur qui partage le réseau du nôtre) | Panel de l'école |
| 8080 | Notre SIEM (`my_siem`) | Panel de l'école |
| `127.0.0.11` | DNS interne de Docker | Local uniquement |

### Comment les sources ont été identifiées

- **7681 et 8080** : relevé des connexions entrantes avec `ss -Htan` pendant 90 s, en ouvrant le panel. Seule `10.10.10.1` s'y connecte.
- **6379 et 25** : ajout d'un log au bloc `stream` de nginx (voir [nginx](#nginx)). Le checker arrive depuis `192.168.1.1`.
- **80** : `access.log` de nginx. `192.168.1.1` (checker) est de loin la première source, mais des visiteurs arrivent aussi avec leur vraie IP, et une partie du trafic passe par `10.10.10.1`.

### Règles appliquées

Sortie attendue de `sudo iptables -S INPUT` :

```
-P INPUT DROP
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -s 10.10.10.1/32 -p tcp -m tcp --dport 7681 -j ACCEPT
-A INPUT -s 10.10.10.1/32 -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
-A INPUT -s 192.168.1.1/32 -p tcp -m tcp --dport 6379 -j ACCEPT
```

| Règle | Pourquoi |
| ----- | -------- |
| Politique `DROP` | Tout ce qui n'est pas listé est refusé. |
| `f2b-sshd` | Chaîne ajoutée par fail2ban : les IP bannies sont rejetées avant toute autre règle. |
| `RELATED,ESTABLISHED` | Les réponses aux connexions déjà acceptées passent. |
| 22, 25, 80 ouverts à tous | Services utilisés et surveillés par le checker. |
| 443 | Règle d'origine des organisateurs, conservée telle quelle. |
| `lo` | Trafic local du conteneur. |
| 7681 et 8080 depuis `10.10.10.1` | Le panel de l'école garde l'accès au terminal web et au SIEM ; les autres conteneurs du réseau Docker (autres équipes) ne peuvent plus les joindre. |
| ICMP | Garde le `ping` pour le diagnostic. |
| 6379 depuis `192.168.1.1` | Seul le checker peut parler à Redis à travers le bastion. |

La politique `OUTPUT` reste `ACCEPT` : le bastion doit pouvoir joindre les services internes, le DNS et les dépôts `apt`.

Depuis Internet, seuls les ports redirigés par la passerelle (22X → 22, 80X → 80) atteignent le bastion. La politique `DROP` protège donc surtout contre le réseau interne : autres équipes, machine du LAN compromise. Le compteur de la politique (`sudo iptables -L INPUT -v -n`, première ligne) mesure ces tentatives et peut servir d'alerte dans le SIEM.

### Procédure de modification sans se bloquer dehors

Toujours garder une session SSH **et** le terminal web ouverts.

1. Armer un filet de sécurité qui rouvre tout dans 3 minutes, sauf validation :

   ```sh
   sudo rm -f /root/fw-ok
   sudo sh -c 'sleep 180; [ -f /root/fw-ok ] || iptables -P INPUT ACCEPT' &
   ```

2. Ajouter les règles avec `iptables -A`, **jamais** `iptables -F` (qui effacerait aussi la chaîne de fail2ban et les règles des organisateurs).
3. Tester : nouvelle connexion SSH, `whoami` dans le terminal web, page du SIEM dans le panel, **les 7 services verts** sur la page de statut (attendre au moins 30 s, le temps d'un passage du checker).
4. Si tout est vert, valider : `sudo touch /root/fw-ok`. Sinon, ne rien faire : la politique revient à `ACCEPT` au bout de 3 minutes.

Pour une règle qui restreint un service plutôt que la politique (comme le 6379), le filet remet la règle ouverte :

```sh
sudo sh -c 'sleep 120; [ -f /root/fw-ok ] || iptables -A INPUT -p tcp --dport 6379 -j ACCEPT' &
```

En cas de problème immédiat : `sudo iptables -P INPUT ACCEPT` rouvre tout, depuis SSH ou depuis le terminal web.

### Incident : service mail tombé

Le port 25 avait d'abord été bloqué, en le prenant pour un leurre. Le service `mail` est passé au rouge : le checker teste ce port. Retour arrière avec `iptables -P INPUT ACCEPT`, puis ajout de la règle du 25. Leçon : identifier ce que fait chaque port en écoute (ici avec `nginx -T`) avant de le fermer.

### Vérifications

```sh
sudo iptables -S INPUT                       # comparer à la liste ci-dessus
sudo iptables -S INPUT | sort | uniq -d      # aucun doublon : sortie vide
sudo iptables -S INPUT | grep 6379           # une seule ligne, avec -s 192.168.1.1/32
sudo iptables -L INPUT -v -n --line-numbers  # compteurs : chaque règle utile doit augmenter
```

## Script de redémarrage (`start-secu.sh`)

Les règles iptables, rsyslog et fail2ban disparaissent au redémarrage du conteneur. Après chaque redémarrage :

```sh
sudo start-secu.sh
```

Fichier `/usr/local/sbin/start-secu.sh` (droits `700`, root uniquement) :

```sh
#!/bin/sh
# Relance les services de sécurité après un redémarrage du conteneur

# rsyslog (logs SSH -> /var/log/auth.log)
if ! pgrep -x rsyslogd >/dev/null; then
    rm -f /run/rsyslogd.pid
    rsyslogd 2>/dev/null
fi

# fail2ban
mkdir -p /run/fail2ban
if ! fail2ban-client ping >/dev/null 2>&1; then
    fail2ban-client start >/dev/null
fi

# Firewall : -C vérifie si la règle existe, -A l'ajoute sinon
add_rule() { iptables -C INPUT "$@" 2>/dev/null || iptables -A INPUT "$@"; }
add_rule -i lo -j ACCEPT
add_rule -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
add_rule -p tcp --dport 22   -j ACCEPT
add_rule -p tcp --dport 25   -j ACCEPT
add_rule -p tcp --dport 80   -j ACCEPT
add_rule -p tcp --dport 443  -j ACCEPT
iptables -D INPUT -p tcp -m tcp --dport 6379 -j ACCEPT 2>/dev/null
add_rule -p tcp --dport 6379 -s 192.168.1.1 -j ACCEPT
add_rule -p tcp --dport 7681 -s 10.10.10.1 -j ACCEPT
add_rule -p tcp --dport 8080 -s 10.10.10.1 -j ACCEPT
add_rule -p icmp -j ACCEPT
iptables -P INPUT DROP

# Récapitulatif
echo "rsyslog  : $(pgrep -x rsyslogd >/dev/null && echo OK || echo KO)"
echo "fail2ban : $(fail2ban-client ping >/dev/null 2>&1 && echo OK || echo KO)"
echo "firewall : $(iptables -S INPUT | head -1)"
```

- Le script peut être relancé autant de fois que nécessaire : `iptables -C` évite les doublons.
- Il remet aussi les règles des organisateurs : si elles ont disparu, le passage en `DROP` ne coupe pas SSH.
- La ligne `iptables -D ... 6379` supprime la règle ouverte des organisateurs si elle revient.

Test effectué : suppression de la règle ICMP, relance du script, la règle est revenue.

## nginx

nginx (PID 19, lancé sans systemd) publie les services internes. Toujours tester avant de recharger : `sudo nginx -t && sudo nginx -s reload`. Le rechargement ne coupe pas les connexions en cours. Une sauvegarde est faite avant chaque modification (`/root/nginx.conf.bak*`, `/root/hopitalmande.fr.bak`).

### Version masquée et vieux TLS retirés

Dans le bloc `http` de `/etc/nginx/nginx.conf` :

```nginx
server_tokens off;
ssl_protocols TLSv1.2 TLSv1.3;
```

`server_tokens off` retire le numéro de version des réponses : un attaquant ne sait plus quelles failles chercher. TLS 1.0 et 1.1 sont obsolètes. Vérification : `curl -sI http://127.0.0.1 | grep -i '^server'` affiche `Server: nginx`, sans version.

### Vhost `ehr` retiré

La machine `ehr` a été retirée de l'infrastructure par les organisateurs. Son entrée `/etc/hosts` a été commentée, ce qui a rendu la configuration nginx invalide : nginx vérifie au chargement que chaque nom de `proxy_pass` existe.

Le bloc `server` d'`ehr.hopitalmande.fr` (lignes 10 à 17 de `/etc/nginx/sites-enabled/hopitalmande.fr`) a été commenté. Les requêtes vers ce nom tombent désormais sur la page par défaut du bastion (`200` au lieu de `502`).

> **Attention** : si une entrée `/etc/hosts` utilisée par nginx disparaît (`mail`, `runner`, `results`, `orthanc`, `redis`), nginx ne pourra plus redémarrer, et tous les services web, Redis et le mail tomberont en même temps. Lancer `sudo nginx -t` après toute modification de `/etc/hosts`.

Vérifier tous les sites, comme le checker :

```sh
for h in mail runner storage orthanc results ehr; do
  printf "%-10s " $h
  curl -s -o /dev/null -w "%{http_code}\n" -H "Host: $h.hopitalmande.fr" http://127.0.0.1
done
```

Attendu : `200` pour runner, storage, results et ehr ; `401` pour mail et orthanc (authentification HTTP Basic).

### Log des ports 25 et 6379

Le bloc `stream` (Redis et SMTP) n'avait aucun log. Ajout en tête du bloc `stream` de `/etc/nginx/nginx.conf` :

```nginx
log_format stream_basic '$time_iso8601 $remote_addr:$remote_port -> :$server_port '
                        '$protocol $status sent=$bytes_sent recv=$bytes_received '
                        'duree=$session_time upstream=$upstream_addr';
access_log /var/log/nginx/stream.log stream_basic;
```

C'est le seul endroit où l'on voit l'IP réelle des clients Redis et SMTP : les serveurs internes voient toutes les connexions venir du bastion.

```sh
sudo awk '{split($2,a,":"); print a[1], "->", $4}' /var/log/nginx/stream.log | sort | uniq -c | sort -rn
```

### Log web enrichi pour le SIEM

Le log par défaut (`access.log`) n'indique ni le site visé ni l'en-tête `X-Forwarded-For`. Ajout dans le bloc `http`, sous `access_log /var/log/nginx/access.log;` (le fichier existant reste inchangé) :

```nginx
log_format siem '$remote_addr - $remote_user [$time_local] "$host" "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                'xff="$http_x_forwarded_for"';
access_log /var/log/nginx/access_siem.log siem;
```

Question en cours : est-ce que le proxy de l'école (`10.10.10.1`) transmet la vraie IP des visiteurs ?

```sh
sudo grep '^10.10.10.1 ' /var/log/nginx/access_siem.log | grep -o 'xff="[^"]*"' | sort | uniq -c | sort -rn | head
```

Si oui, nginx pourra utiliser cette IP (`set_real_ip_from` / `real_ip_header`), et fail2ban pourra bannir les attaquants qui passent par ce proxy.

## Redis

Le port 6379 du bastion transmet directement au Redis interne (`redis.hopital.lan`, Redis 5.0.14, sans mot de passe). Un client Redis non authentifié peut utiliser `CONFIG SET` pour écrire un fichier arbitraire sur le serveur (clé SSH, tâche cron) et en prendre le contrôle.

| Mesure | État |
| ------ | ---- |
| Port 6379 du bastion réservé au checker (`192.168.1.1`) | Fait (voir [Firewall](#firewall)) |
| Mot de passe Redis | Impossible : le checker envoie `PING` sans s'authentifier, Redis répondrait `NOAUTH` et le service passerait au rouge |
| Désactiver les commandes dangereuses | À demander aux organisateurs : nous n'avons pas d'accès SSH au serveur Redis |

Lignes à proposer aux organisateurs pour `redis.conf` (le `PING` du checker continue de fonctionner) :

```
rename-command CONFIG ""
rename-command SLAVEOF ""
rename-command REPLICAOF ""
rename-command MODULE ""
rename-command DEBUG ""
```

La règle du bastion ne protège que le chemin qui passe par lui : Redis reste joignable directement sur le LAN (`192.168.1.106:6379`), notamment depuis le runner.

### Détection pour le SIEM

L'attaque laisse une trace : elle change `dir` et `dbfilename`. Lecture seule, depuis le bastion, sans rien installer :

```sh
redis_get() {
  exec 3<>/dev/tcp/192.168.1.106/6379
  printf 'CONFIG GET %s\r\n' "$1" >&3
  timeout 2 cat <&3 | tr -d '\r' | sed -n '5p'
  exec 3<&-
}
echo "dir        = $(redis_get dir)"
echo "dbfilename = $(redis_get dbfilename)"
```

Relever les valeurs normales, puis alerter si elles changent (par exemple `dir = /root/.ssh` ou `dbfilename = authorized_keys`).

## Pistes écartées

| Piste | Pourquoi elle a été écartée |
| ----- | --------------------------- |
| VPN WireGuard | WireGuard fonctionne en UDP, et la passerelle de l'école ne redirige que du TCP. Il aurait fallu un port UDP ouvert par les organisateurs. |
| Tailscale | Pas de `/dev/net/tun` (mode userspace seulement), rien ne survit à un redémarrage du conteneur, et cela contourne la passerelle de l'école sans son accord. |
| Fermer complètement le 22 | Sans VPN, c'est la seule porte d'entrée. SSH est donc durci sur place. |
| Tuer le terminal web (7681) | Impossible (il tourne dans un autre conteneur) et inutile : c'est notre console de secours. Il est filtré par IP à la place. |

## Points ouverts

| Priorité | Point | Action |
| -------- | ----- | ------ |
| Critique | Le runner exécute du code Python arbitraire et est accessible depuis Internet (`runner.hopitalmande.fr`). Il peut joindre tout le LAN, Redis compris, sans passer par le bastion. | Restreindre son vhost nginx, sans casser le test HTTP 200 du checker |
| Haute | Commandes dangereuses de Redis actives | Demande aux organisateurs (voir [Redis](#redis)) |
| Moyenne | Aucun HTTPS : les identifiants d'Orthanc et du portail de résultats circulent en clair | Certificat et configuration TLS dans nginx |
| Moyenne | Jail `nginx-401` | Finaliser (voir [Jail web](#jail-web-codes-401--à-finaliser)) |
| Moyenne | Pas de limite de tentatives sur le login du portail de résultats | `limit_req` dans nginx, une fois l'URL de login identifiée |
| Moyenne | IP réelle derrière `10.10.10.1` | Vérifier `X-Forwarded-For` dans `access_siem.log` |
| Basse | [amelioration-bastion.md](amelioration-bastion.md) prévoit `DenyUsers admin`, absent de `50-hardening.conf` | Rajouter la ligne, ou mettre la doc à jour |
| Basse | La clé `lp1@starlite` d'`admin` (d'origine inconnue) a été déplacée dans `/root/admin_authorized_keys.bak` | Demander aux organisateurs si c'est la leur, et la remettre le cas échéant |
| Basse | `IdentitiesOnly yes` chez julian, rulian et le prof | À vérifier avec chacun |
