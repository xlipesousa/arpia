sudo apt update
sudo apt install gvm
sudo gvm-setup
sudo gvm-check-setup

iniciando o gvm:
sudo gvm-start
Usuário sudo: kali
senha: kali

Mensagem do terminal após startar o gvm:
┌──(kali㉿kali)-[~]
└─$ sudo gvm-start
[sudo] password for kali: 
[>] Please wait for the GVM services to start.
[>]
[>] You might need to refresh your browser once it opens.
[>]
[>]  Web UI (Greenbone Security Assistant): https://127.0.0.1:9392

● gsad.service - Greenbone Security Assistant daemon (gsad)
     Loaded: loaded (/usr/lib/systemd/system/gsad.service; disabled; preset: disabled)
     Active: active (running) since Tue 2025-10-28 16:12:57 EDT; 37ms ago
 Invocation: f3c843cecf444684a32e4475c8c4358b
       Docs: man:gsad(8)
             https://www.greenbone.net
   Main PID: 17595 (gsad)
      Tasks: 1 (limit: 11883)
     Memory: 1.2M (peak: 1.9M)
        CPU: 17ms
     CGroup: /system.slice/gsad.service
             └─17595 /usr/sbin/gsad --foreground --listen 127.0.0.1 --port 9392

Oct 28 16:12:57 kali systemd[1]: Starting gsad.service - Greenbone Security Assistant daemon (gsad)...
Oct 28 16:12:57 kali systemd[1]: Started gsad.service - Greenbone Security Assistant daemon (gsad).

● gvmd.service - Greenbone Vulnerability Manager daemon (gvmd)
     Loaded: loaded (/usr/lib/systemd/system/gvmd.service; disabled; preset: disabled)
     Active: active (running) since Tue 2025-10-28 16:12:52 EDT; 5s ago
 Invocation: 73247431b1bb455fa6a1dc5295c076ee
       Docs: man:gvmd(8)
    Process: 17515 ExecStart=/usr/sbin/gvmd --osp-vt-update=/run/ospd/ospd.sock --listen-group=_gvm (code=exited, status=0/SUCCESS)
   Main PID: 17517 (gvmd)
      Tasks: 3 (limit: 11883)
     Memory: 63.7M (peak: 63.9M)
        CPU: 4.936s
     CGroup: /system.slice/gvmd.service
             ├─17517 "gvmd: Waiting " --osp-vt-update=/run/ospd/ospd.sock --listen-group=_gvm
             ├─17543 "gvmd: Synchron" --osp-vt-update=/run/ospd/ospd.sock --listen-group=_gvm
             └─17546 "gvmd: Syncing " --osp-vt-update=/run/ospd/ospd.sock --listen-group=_gvm

Oct 28 16:12:51 kali systemd[1]: Starting gvmd.service - Greenbone Vulnerability Manager daemon (gvmd)...
Oct 28 16:12:51 kali systemd[1]: gvmd.service: Can't open PID file '/run/gvmd/gvmd.pid' (yet?) after start: No such file or directory
Oct 28 16:12:52 kali systemd[1]: Started gvmd.service - Greenbone Vulnerability Manager daemon (gvmd).

● ospd-openvas.service - OSPd Wrapper for the OpenVAS Scanner (ospd-openvas)
     Loaded: loaded (/usr/lib/systemd/system/ospd-openvas.service; disabled; preset: disabled)
     Active: active (running) since Tue 2025-10-28 16:12:51 EDT; 6s ago
 Invocation: ac9d2a6b98af4c49b5ecf33edb2b9209
       Docs: man:ospd-openvas(8)
             man:openvas(8)
    Process: 17446 ExecStart=/usr/bin/ospd-openvas --config /etc/gvm/ospd-openvas.conf --log-config /etc/gvm/ospd-logging.conf (code=exited, status=0/SUCCESS)
   Main PID: 17497 (ospd-openvas)
      Tasks: 5 (limit: 11883)
     Memory: 61.8M (peak: 102M)
        CPU: 2.053s
     CGroup: /system.slice/ospd-openvas.service
             ├─17497 /usr/bin/python3 /usr/bin/ospd-openvas --config /etc/gvm/ospd-openvas.conf --log-config /etc/gvm/ospd-logging.conf
             └─17499 /usr/bin/python3 /usr/bin/ospd-openvas --config /etc/gvm/ospd-openvas.conf --log-config /etc/gvm/ospd-logging.conf

Oct 28 16:12:48 kali systemd[1]: Starting ospd-openvas.service - OSPd Wrapper for the OpenVAS Scanner (ospd-openvas)...
Oct 28 16:12:51 kali systemd[1]: Started ospd-openvas.service - OSPd Wrapper for the OpenVAS Scanner (ospd-openvas).

[>] Opening Web UI (https://127.0.0.1:9392) in: 5... 4... 3... 2... 1... 



a aplicação web não é nosso foco, mas está rodando no endereço
https://127.0.0.1:9392
Logando na interface web
usuário: admin
Senha: kali