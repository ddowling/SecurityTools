/* client.c */
/*
Copyright 2003 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is 
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <sys/select.h>
#include <sys/time.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/session.h>
#include <libssh/ssh1.h>

#include <fcntl.h>

char *host;

static void usage(){
    fprintf(stderr,"Usage : sshscan [options] [login@]hostname\n"
	    "Query SSH servers and retrieve information\n"
	    "Options :\n"
	    "  -p port : connect to port\n");
    exit(0);
}

static int opts(int argc, char **argv){
    int i;
    while((i=getopt(argc,argv,""))!=-1){
        switch(i){
            default:
                fprintf(stderr,"unknown option %c\n",optopt);
                usage();
        }
    }
    if(optind < argc)
        host=argv[optind++];
    if(host==NULL)
        usage();
    return 0;
}


void analyse_banner(const char *banner, char *version,
		    int *ssh1_allowed, int *ssh2_allowed)
{
    if (strlen(banner) > 4)
    {
	const char *p;
	char *v = version;
	for(p = banner + 4; *p != '-' && *p != '\0'; p++)
	    *v++ = *p;
	*v = '\0';
    }
    else
    	version[0] = '\0';

    switch(version[0])
    {
    case '1':
	*ssh1_allowed = 1;
	if (version[2] == '9')
	    *ssh2_allowed = 1;
	else
	    *ssh2_allowed = 0;
	break;
    case '2':
	*ssh1_allowed = 0;
	*ssh2_allowed = 1;
	break;
    default:
	*ssh1_allowed = 0;
	*ssh2_allowed = 0;
    }
}

static int server_bits = 0;
static int host_bits = 0;
static unsigned long protocol_flags = 0;
static unsigned long supported_ciphers_mask = 0;
static unsigned long supported_authentications_mask = 0;

struct mask_str
{
    int mask;
    const char *str;
};

struct mask_str ssh1_cipher_masks[] =
{
    { 1 << SSH_CIPHER_NONE, "none" },
    { 1 << SSH_CIPHER_IDEA, "idea-cfb" },
    { 1 << SSH_CIPHER_DES, "des-cbc" },
    { 1 << SSH_CIPHER_3DES, "3des-cdc" },
    { 1 << SSH_CIPHER_RC4, "rc4" },
    { 1 << SSH_CIPHER_BLOWFISH, "blowfish" }
};

struct mask_str ssh1_auth_masks[] =
{
    { 1 << SSH_AUTH_RHOSTS, "rhosts" },
    { 1 << SSH_AUTH_RSA, "rsa" },
    { 1 << SSH_AUTH_PASSWORD, "password" },
    { 1 << SSH_AUTH_RHOSTS_RSA, "rhosts-rsa" },
    { 1 << SSH_AUTH_TIS, "tis" },
    { 1 << SSH_AUTH_KERBEROS, "kerberos" },
};

struct mask_str ssh_auth_methods[] =
{
    { SSH_AUTH_METHOD_UNKNOWN, "unknown" },
    { SSH_AUTH_METHOD_NONE, "none" },
    { SSH_AUTH_METHOD_PASSWORD, "password" },
    { SSH_AUTH_METHOD_PUBLICKEY, "public key" },
    { SSH_AUTH_METHOD_HOSTBASED, "host based" },
    { SSH_AUTH_METHOD_INTERACTIVE, "interactive" },
};

void process_log_callback(ssh_session session, int priority,
			  const char *message, void *userdata)
{
    printf("LOG: priority=%d message=%s\n",
	   priority, message);

    // Want to decode the following message from the SSHv1 connection logs
    // Unfortunately there is no other way to get this information
    // Server bits: 768; Host bits: 2048; Protocol flags: 00000002; Cipher mask: 00000048; Auth mask: 0000000c
    const char *start_str = "Server bits: ";
    if (priority == SSH_LOG_PROTOCOL &&
	strncmp(message, start_str, strlen(start_str)) == 0)
    {
	server_bits = 0;
	host_bits = 0;
	protocol_flags = 0;
	supported_ciphers_mask = 0;
	supported_authentications_mask = 0;
	int n = sscanf(message,
	       "Server bits: %d; Host bits: %d; Protocol flags: %8lx; "
	       "Cipher mask: %8lx; Auth mask: %8lx",
	       &server_bits,
	       &host_bits,
	       &protocol_flags,
	       &supported_ciphers_mask,
	       &supported_authentications_mask);

	printf("Decoded %d fields\n", n);
	printf("Server bits: %d; Host bits: %d; Protocol flags: %.8lx; "
	       "Cipher mask: %.8lx; Auth mask: %.8lx\n",
	       server_bits,
	       host_bits,
	       protocol_flags,
	       supported_ciphers_mask,
	       supported_authentications_mask);
    }
}

int main(int argc, char **argv)
{
    opts(argc,argv);

    int test_pass;
// FIXME just test SSH1
//    for(test_pass = 1; test_pass < 2; test_pass++)
    for(test_pass = 0; test_pass < 2; test_pass++)
    {
	printf("Test pass %d\n", test_pass);

	ssh_session session = ssh_new();

	struct ssh_callbacks_struct cb;
	memset(&cb, 0, sizeof(cb));
	cb.auth_function = NULL;
	cb.log_function = process_log_callback;
	cb.userdata = NULL;

	ssh_callbacks_init(&cb);
	ssh_set_callbacks(session,&cb);

	// Need at least 2 here to catch the cipher and key length information
	int verbosity = 2;
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

	ssh_options_set(session, SSH_OPTIONS_HOST, host);

	// First test is for both SSH2 and SSH1.
	// By default it will connect with preference for SSH2.
	// Second pass will be just SSH1. This pass is only called if we connect with SSH2
	// and then find that SSH1 is also supported
	int support_ssh2 = (test_pass == 0);
	int support_ssh1 = 1;
	ssh_options_set(session, SSH_OPTIONS_SSH2, &support_ssh2);
	ssh_options_set(session, SSH_OPTIONS_SSH1, &support_ssh1);

	int connection_status = ssh_connect(session);

	// Ignore the connection status but if we have no banner then quit
	if (session->serverbanner == 0)
	{
	    fprintf(stderr,"Connection failed : %s\n", ssh_get_error(session));
	    ssh_disconnect(session);
	    ssh_finalize();
	    return 1;
	}

	// Dump out banners
	int ssh1_allowed;
	int ssh2_allowed;
	char version[10];
	analyse_banner(session->serverbanner, version, &ssh1_allowed, &ssh2_allowed);

	// Output protocols
	printf("Protocol Version: %s\n", version);
	printf("SSH1 Allowed : %s\n", ssh1_allowed ? "Yes" : "No");
	printf("SSH2 Allowed : %s\n", ssh2_allowed ? "Yes" : "No");
	printf("Server banner : %s\n", session->serverbanner);

	// version holds the indication of either SSHv1 or SSHv2 connection
	printf("version : %d\n", session->version);

	// Dump out the KEX information
	extern const char *ssh_kex_nums[];
	KEX *kex = &session->server_kex;
	printf("Server Kex\n");
	if (kex == 0 || kex->methods == 0)
	    printf("No KEX parameters\n");
	else
	{
	    int i;
	    for(i = 0; i < 10; i++)
	    {
		printf("%s: %s\n", ssh_kex_nums[i], kex->methods[i]);
	    }
	}

	// Check connection status after we have dumped out some information
	// Otherwise incompatible cipher suites for client and server just
	// terminate the applicationy
	if (connection_status != 0)
	{
	    fprintf(stderr,"Connection failed : %s\n", ssh_get_error(session));
	    ssh_disconnect(session);
	    ssh_finalize();
	    return 1;
	}

	unsigned char *hash = NULL;
	int hlen = ssh_get_pubkey_hash(session, &hash);
	if (hlen < 0)
	{
	    ssh_disconnect(session);
	    ssh_finalize();
	    return 1;
	}

	ssh_print_hexa("Public key hash", hash, hlen);
	free(hash);

	ssh_userauth_none(session, NULL);

	int auth = ssh_auth_list(session);
	printf("auth: 0x%04x\n", auth);
	printf("supported auth methods: ");
	if (auth & SSH_AUTH_METHOD_PASSWORD)
	{
	    printf("password, ");
	}
	if (auth & SSH_AUTH_METHOD_PUBLICKEY)
	{
	    printf("publickey, ");
	}
	if (auth & SSH_AUTH_METHOD_HOSTBASED)
	{
	    printf("hostbased, ");
	}
	if (auth & SSH_AUTH_METHOD_INTERACTIVE)
	{
	    printf("keyboard-interactive");
	}
	printf("\n");

	auth = ssh_userauth_autopubkey(session, NULL);
	if(auth == SSH_AUTH_ERROR)
	{
	    fprintf(stderr,"Authenticating with pubkey: %s\n",ssh_get_error(session));
	    ssh_finalize();
	    return -1;
	}

	char *banner = ssh_get_issue_banner(session);
	if(banner)
	{
	    printf("%s\n",banner);
	    free(banner);
	}

	ssh_disconnect(session);

	ssh_finalize();

	// Check if we need to perform the second pass?
	if (!ssh1_allowed || !ssh2_allowed)
	    break;
    }


    return 0;
}
