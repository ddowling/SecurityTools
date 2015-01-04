#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* We don't have SA_LEN defined in MidnightBSD */
#ifndef SA_LEN
#ifdef HAVE_SOCKADDR_SA_LEN
#define SA_LEN(addr)    ((addr)->sa_len)
#else /* HAVE_SOCKADDR_SA_LEN */
#ifdef HAVE_SOCKADDR_STORAGE
#define SA_LEN(addr)    (sizeof (struct sockaddr_storage))
#else /* HAVE_SOCKADDR_STORAGE */
#define SA_LEN(addr)    (sizeof (struct sockaddr))
#endif /* HAVE_SOCKADDR_STORAGE */
#endif /* HAVE_SOCKADDR_SA_LEN */
#endif /* SA_LEN */

/*
 * NTP definitions.  Note that these assume 8-bit bytes - sigh.  There
 * is little point in parameterising everything, as it is neither
 * feasible nor useful.  It would be very useful if more fields could
 * be defined as unspecified.  The NTP packet-handling routines
 * contain a lot of extra assumptions.
 */

#define JAN_1970   2208988800.0		/* 1970 - 1900 in seconds */
#define NTP_SCALE  4294967296.0		/* 2^32, of course! */

#define NTP_MODE_CLIENT       3		/* NTP client mode */
#define NTP_MODE_SERVER       4		/* NTP server mode */
#define NTP_VERSION           4		/* The current version */
#define NTP_VERSION_MIN       1		/* The minum valid version */
#define NTP_VERSION_MAX       4		/* The maximum valid version */
#define NTP_STRATUM_MAX      14		/* The maximum valid stratum */
#define NTP_INSANITY     3600.0		/* Errors beyond this are hopeless */

#define NTP_PACKET_MIN       48		/* Without authentication */
#define NTP_PACKET_MAX       68		/* With authentication (ignored) */

#define NTP_DISP_FIELD        8		/* Offset of dispersion field */
#define NTP_REFERENCE        16		/* Offset of reference timestamp */
#define NTP_ORIGINATE        24		/* Offset of originate timestamp */
#define NTP_RECEIVE          32		/* Offset of receive timestamp */
#define NTP_TRANSMIT         40		/* Offset of transmit timestamp */

#define STATUS_NOWARNING      0		/* No Leap Indicator */
#define STATUS_LEAPHIGH       1		/* Last Minute Has 61 Seconds */
#define STATUS_LEAPLOW        2		/* Last Minute Has 59 Seconds */
#define STATUS_ALARM          3		/* Server Clock Not Synchronized */

#define MAX_QUERIES         25
#define MAX_DELAY           15

#define MILLION_L    1000000l		/* For conversion to/from timeval */
#define MILLION_D       1.0e6		/* Must be equal to MILLION_L */

struct ntp_data {
	u_char		status;
	u_char		version;
	u_char		mode;
	u_char		stratum;
	double		receive;
	double		transmit;
	double		current;
	u_int64_t	recvck;

	/* Local State */
	double		originate;
	u_int64_t	xmitck;
};

void ntp_client(const char *, int, struct timeval *, struct timeval *, int);
int sync_ntp(int, const struct sockaddr *, const char *, double *, double *);
int write_packet(int, struct ntp_data *);
int read_packet(int, struct ntp_data *, double *, double *);
void unpack_ntp(struct ntp_data *, u_char *);
double current_time(double);
void create_timeval(double, struct timeval *, struct timeval *);
void print_packet(const struct ntp_data *);

#ifdef LEAP_SECONDS
int corrleaps;
#endif

int debug = 0;

#ifdef LEAP_SECONDS
void ntpleaps_init()
{
    // FIXME
}
#endif

void ntp_client(const char *hostname, int family, struct timeval *new_time,
		struct timeval *adjust, int leapflag)
{
    struct addrinfo hints, *res0, *res;
    double offset, error;
    int accept = 0, ret, s, ierror;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    ierror = getaddrinfo(hostname, "ntp", &hints, &res0);
    if (ierror) {
	fprintf(stderr, "%s: %s", hostname, strerror(ierror));
	exit(1);
    }

#ifdef LEAP_SECONDS
    corrleaps = leapflag;
    if (corrleaps)
	ntpleaps_init();
#endif

    s = -1;
    for (res = res0; res; res = res->ai_next)
    {
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0)
	    continue;

	ret = sync_ntp(s, res->ai_addr, hostname, &offset, &error);
	if (ret < 0)
	{
	    if (debug)
		fprintf(stderr, "try the next address\n");

	    close(s);
	    s = -1;

	    continue;
	}

	accept++;
	break;
    }
    freeaddrinfo(res0);

    if (debug)
	fprintf(stderr, "Correction: %.6f +/- %.6f\n", offset, error);

    if (accept < 1)
    {
	fprintf(stderr, "Unable to get a reasonable time estimate\n");
	exit(1);
    }

    create_timeval(offset, new_time, adjust);
}

int sync_ntp(int fd, const struct sockaddr *peer, const char *hostname,
	     double *offset, double *error)
{
    int attempts = 0, accepts = 0, rejects = 0;
    int delay = MAX_DELAY, ret;
    double deadline;
    double a, b, x, y;
    double minerr = 0.1;		/* Maximum ignorable variation */
    struct ntp_data data;

    deadline = current_time(JAN_1970) + delay;
    *offset = 0.0;
    *error = NTP_INSANITY;

#ifdef HAVE_SOCKADDR_SA_LEN
    printf("have sockaddr sa length\n");
#endif
#ifdef HAVE_SOCKADDR_STORAGE
    printf("have sockaddr storage\n");
#endif

    if (connect(fd, peer, SA_LEN(peer)) < 0) {
	fprintf(stderr, "Failed to connect to server\n");
	return -1;
    }

    while (accepts < MAX_QUERIES && attempts < 2 * MAX_QUERIES) 
    {
	memset(&data, 0, sizeof(data));

	if (current_time(JAN_1970) > deadline) {
	    fprintf(stderr, "Not enough valid responses received in time\n");
	    return -1;
	}

	if (debug)
	    printf("Send packet to NTP server\n");

	if (write_packet(fd, &data) < 0)
	    return -1;

	if (debug)
	    printf("Waiting for a response\n");

	ret = read_packet(fd, &data, &x, &y);

	if (debug)
	{
	    printf("read_packet returned %d\n", ret);
	    print_packet(&data);
	}


	if (ret < 0)
	    return -1;
	else if (ret > 0)
	{
	    if (++rejects > MAX_QUERIES) {
		fprintf(stderr, "Too many bad or lost packets\n");
		return -1;
	    } else
		continue;
	} else
	    ++accepts;


	if (debug)
	    fprintf(stderr, "Offset: %.6f +/- %.6f\n", x, y);

	if ((a = x - *offset) < 0.0)
	    a = -a;
	if (accepts <= 1)
	    a = 0.0;
	b = *error + y;
	if (y < *error)
	{
	    *offset = x;
	    *error = y;
	}

	if (debug)
	    fprintf(stderr, "Best: %.6f +/- %.6f\n", *offset, *error);

	if (a > b) {
	    fprintf(stderr, "Inconsistent times received from NTP server\n");
	    return -1;
	}

	if ((data.status & STATUS_ALARM) == STATUS_ALARM) {
	    fprintf(stderr, "Ignoring NTP server wtih alarm flag set\n");
	    return -1;
	}

	if (*error <= minerr)
	    break;
    }

    if (accepts > 0)
    {
	const char *address = "?";
	if (peer->sa_family == AF_INET)
	{
	    struct sockaddr_in *peer_in = (struct sockaddr_in *)peer;
	    address = inet_ntoa(peer_in->sin_addr);
	}

	char primary_hostname[NI_MAXHOST];
	getnameinfo(peer, sizeof(struct sockaddr),
		    primary_hostname, NI_MAXHOST, NULL, 0, 0);

	printf("NTP Server %s:\n", hostname);
	printf("              Address: %s\n", address);
	printf("    Primary Hostname : %s\n", primary_hostname);
	printf("    Protocol Version : %d\n", data.version);
	printf("             Stratum : %d\n", data.stratum);
	printf("               Offset: %.6f +/- %.6f seconds\n", *offset, *error);

	printf("\n");
    }

    return accepts;
}

/* Send out NTP packet. */
int
write_packet(int fd, struct ntp_data *data)
{
    u_char	packet[NTP_PACKET_MIN];
    ssize_t	length;

    memset(packet, 0, sizeof(packet));

    packet[0] = (NTP_VERSION << 3) | (NTP_MODE_CLIENT);

    data->xmitck = (u_int64_t)random() << 32 | random();

    /*
     * Send out a random 64-bit number as our transmit time.  The NTP
     * server will copy said number into the originate field on the
     * response that it sends us.  This is totally legal per the SNTP spec.
     *
     * The impact of this is two fold: we no longer send out the current
     * system time for the world to see (which may aid an attacker), and
     * it gives us a (not very secure) way of knowing that we're not
     * getting spoofed by an attacker that can't capture our traffic
     * but can spoof packets from the NTP server we're communicating with.
     *
     * No endian concerns here.  Since we're running as a strict
     * unicast client, we don't have to worry about anyone else finding
     * the transmit field intelligible.
     */

    *(u_int64_t *)(packet + NTP_TRANSMIT) = data->xmitck;

    data->originate = current_time(JAN_1970);

    length = write(fd, packet, sizeof(packet));

    if (length != sizeof(packet)) {
	fprintf(stderr, "Unable to send NTP packet to server\n");
	return -1;
    }

    return 0;
}

/*
 * Check the packet and work out the offset and optionally the error.
 * Note that this contains more checking than xntp does. Return 0 for
 * success, 1 for failure. Note that it must not change its arguments
 * if it fails.
 */
int
read_packet(int fd, struct ntp_data *data, double *off, double *error)
{
    u_char	receive[NTP_PACKET_MAX];
    struct	timeval tv;
    double	x, y;
    int	length, r;
    fd_set	*rfds;

    rfds = (fd_set *)calloc(fd + 1, sizeof(fd_mask));
    if (rfds == NULL)
    {
	fprintf(stderr, "calloc\n");
	exit(1);
    }

    FD_SET(fd, rfds);

 retry:
    tv.tv_sec = 0;
    tv.tv_usec = 1000000 * MAX_DELAY / MAX_QUERIES;

    r = select(fd + 1, rfds, NULL, NULL, &tv);

    if (r < 0) {
	if (errno == EINTR)
	    goto retry;
	else
	    fprintf(stderr, "select\n");

	free(rfds);
	return r;
    }

    if (r != 1 || !FD_ISSET(fd, rfds)) {
	free(rfds);
	return 1;
    }

    free(rfds);

    length = read(fd, receive, NTP_PACKET_MAX);

    if (length < 0) {
	fprintf(stderr, "Unable to receive NTP packet from server\n");
	return -1;
    }

    if (length < NTP_PACKET_MIN || length > NTP_PACKET_MAX) {
	fprintf(stderr, "Invalid NTP packet size, packet rejected\n");
	return 1;
    }

    unpack_ntp(data, receive);

    if (data->recvck != data->xmitck) {
	fprintf(stderr, "Invalid cookie received, packet rejected\n");
	return 1;
    }

    if (data->version < NTP_VERSION_MIN ||
	data->version > NTP_VERSION_MAX) {
	fprintf(stderr, "Received NTP version %u, need %u or lower",
	      data->version, NTP_VERSION);
	return 1;
    }

    if (data->mode != NTP_MODE_SERVER) {
	fprintf(stderr, "Invalid NTP server mode, packet rejected\n");
	return 1;
    }

    if (data->stratum > NTP_STRATUM_MAX) {
	fprintf(stderr, "Invalid stratum received, packet rejected\n");
	return 1;
    }

    if (data->transmit == 0.0) {
	fprintf(stderr, "Server clock invalid, packet rejected\n");
	return 1;
    }

    x = data->receive - data->originate;
    y = data->transmit - data->current;

    *off = (x + y) / 2;
    *error = x - y;

    x = (data->current - data->originate) / 2;

    if (x > *error)
	*error = x;

    return 0;
}

/*
 * Unpack the essential data from an NTP packet, bypassing struct
 * layout and endian problems.  Note that it ignores fields irrelevant
 * to SNTP.
 */
void
unpack_ntp(struct ntp_data *data, u_char *packet)
{
    int i;
    double d;

    data->current = current_time(JAN_1970);

    data->status = (packet[0] >> 6);
    data->version = (packet[0] >> 3) & 0x07;
    data->mode = packet[0] & 0x07;
    data->stratum = packet[1];

    for (i = 0, d = 0.0; i < 8; ++i)
	d = 256.0*d+packet[NTP_RECEIVE+i];

    data->receive = d / NTP_SCALE;

    for (i = 0, d = 0.0; i < 8; ++i)
	d = 256.0*d+packet[NTP_TRANSMIT+i];

    data->transmit = d / NTP_SCALE;

    /* See write_packet for why this isn't an endian problem. */
    data->recvck = *(u_int64_t *)(packet + NTP_ORIGINATE);
}

/*
 * Get the current UTC time in seconds since the Epoch plus an offset
 * (usually the time from the beginning of the century to the Epoch)
 */
double
current_time(double offset)
{
    struct timeval current;

    if (gettimeofday(&current, NULL))
    {
	fprintf(stderr, "Could not get local time of day\n");
	exit(1);
    }

#ifdef LEAP_SECONDS
    /*
     * At this point, current has the current TAI time.
     * Now subtract leap seconds to set the posix tick.
     */

    u_int64_t t = SEC_TO_TAI64(current.tv_sec);
    if (corrleaps)
	ntpleaps_sub(&t);

    return offset + TAI64_TO_SEC(t) + 1.0e-6 * current.tv_usec;
#else
    return offset + current.tv_sec + 1.0e-6 * current.tv_usec;
#endif
}

/*
 * Change offset into current UTC time. This is portable, even if
 * struct timeval uses an unsigned long for tv_sec.
 */
void
create_timeval(double difference,
	       struct timeval *new_time,
	       struct timeval *adjust)
{
    struct timeval old;
    long n;

    /* Start by converting to timeval format. Note that we have to
     * cater for negative, unsigned values. */
    if ((n = (long) difference) > difference)
	--n;
    adjust->tv_sec = n;
    adjust->tv_usec = (long) (MILLION_D * (difference-n));
    errno = 0;
    if (gettimeofday(&old, NULL))
    {
	fprintf(stderr, "Could not get local time of day\n");
	exit(1);
    }

    new_time->tv_sec = old.tv_sec + adjust->tv_sec;
    new_time->tv_usec = (n = (long) old.tv_usec + (long) adjust->tv_usec);

    if (n < 0) {
	new_time->tv_usec += MILLION_L;
	--new_time->tv_sec;
    } else if (n >= MILLION_L) {
	new_time->tv_usec -= MILLION_L;
	++new_time->tv_sec;
    }
}

void
print_packet(const struct ntp_data *data)
{
    printf("status:      %u\n", data->status);
    printf("version:     %u\n", data->version);
    printf("mode:        %u\n", data->mode);
    printf("stratum:     %u\n", data->stratum);
    printf("originate:   %f\n", data->originate);
    printf("receive:     %f\n", data->receive);
    printf("transmit:    %f\n", data->transmit);
    printf("current:     %f\n", data->current);
    printf("xmitck:      0x%0llX\n", data->xmitck);
    printf("recvck:      0x%0llX\n", data->recvck);
};

void show_version()
{
     fprintf(stderr, "NTP Check\n");
     fprintf(stderr, "\n");
     fprintf(stderr, "Copyright : Open Source Solutions Pty Ltd\n");
     fprintf(stderr, "Author    : Denis Dowling (dpd@opsol.com.au)\n");
     fprintf(stderr, "Built     : %s %s\n", __DATE__, __TIME__);
     fprintf(stderr, "\n");
}

void usage(const char *prog)
{
    show_version();

    fprintf(stderr, "%s {args} {list of NTP servers}\n",
            prog);

    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "\t-D             : Turn on debugging\n");
    fprintf(stderr, "\t-h             : Show help\n");
    fprintf(stderr, "\t-v             : Show version\n");
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    int family = AF_INET;
    struct timeval new_tv;
    struct timeval adjust_tv;
    int leapflag = 1;
    int i;

    int c;

    opterr = 0;

    const char *arguments = "Dhv";

    while ((c = getopt(argc, argv, arguments)) != -1)
    {
        switch (c)
        {
	case 'D':
            debug = 1;
            break;

	case 'h':
            usage(argv[0]);
            return 0;

	case 'v':
	    show_version();
	    return 0;

        case '?':
            fprintf (stderr, "Unknown argument '%c'\n", optopt);
            opterr++;
            break;

        default:
            fprintf(stderr, "Argument parsing error\n");
            opterr++;
            break;
        }
    }

    if (opterr)
    {
        usage(argv[0]);
        return 1;
    }

    for (i = optind; i < argc; i++)
	ntp_client(argv[i], family, &new_tv, &adjust_tv, leapflag);

    return 1;
}
