#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <infiniband/sa.h>
#include "shared.h"

#define max(a, b) (a > b ? a : b)

static short server_port = 7125;
static int listen_socket;

struct ssa_client {
	pthread_mutex_t lock;
	int             sock;
	int             index;
	//atomic_t        refcnt;
};

static struct ssa_client client_array[FD_SETSIZE - 1];

static void ssa_init_server(void)
{
	FILE *f;
	int i;

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		pthread_mutex_init(&client_array[i].lock, NULL);
		client_array[i].index = i;
		client_array[i].sock = -1;
		//atomic_init(&client_array[i].refcnt);
	}

	if (!(f = fopen("/var/run/ssa_health.port", "w"))) {
		printf("%s: notice - cannot publish ssa health port number\n", __func__);
		return;
	}
	fprintf(f, "%hu\n", server_port);
	fclose(f);
}

static int ssa_listen(void)
{
	struct sockaddr_in addr;
	int ret;

	printf("%s\n", __func__);
	listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_socket == -1) {
		printf("%s: ERROR - unable to allocate listen socket\n", __func__);
		return errno;
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ret = bind(listen_socket, (struct sockaddr *) &addr, sizeof addr);
	if (ret == -1) {
		printf("%s: ERROR - unable to bind listen socket\n", __func__);
		return errno;
	}

	ret = listen(listen_socket, 0);
	if (ret == -1) {
		printf("%s: ERROR - unable to start listen\n", __func__);
		return errno;
	}

	printf("%s: listen active\n", __func__);
	return 0;
}

static void ssa_disconnect_client(struct ssa_client *client)
{
	pthread_mutex_lock(&client->lock);
	shutdown(client->sock, SHUT_RDWR);
	close(client->sock);
	client->sock = -1;
	pthread_mutex_unlock(&client->lock);
	//(void) atomic_dec(&client->refcnt);
}

static int ssa_svr_accept(void)
{
	int s, i;

	printf("%s\n", __func__);
	s = accept(listen_socket, NULL, NULL);
	if (s == -1) {
		printf("%s: ERROR - failed to accept connection\n", __func__ );
		return -1;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		//if (!atomic_get(&client_array[i].refcnt))
		if (client_array[i].sock == -1)
			break;
	}

	if (i == FD_SETSIZE - 1) {
		printf("%s: ERROR - all connections busy - rejecting\n", __func__);
		close(s);
		return -1;
	}

	client_array[i].sock = s;
	//atomic_set(&client_array[i].refcnt, 1);
	printf("%s: assigned client %d\n", __func__, i);
	return i;
}

static void ssa_svr_receive(struct ssa_client *client)
{
	struct ssa_health_msg msg;
	int ret;

	printf("%s: client %d\n", __func__, client->index);
	ret = recv(client->sock, (char *) &msg, sizeof msg, 0);
	if (ret <= 0 || ret != msg.hdr.length) {
		printf("%s: client disconnected\n", __func__);
		ret = 1;
		goto out;
	}

	if (msg.hdr.version != SSA_HEALTH_VERSION) {
		printf("%s: ERROR - unsupported version %d\n", __func__, msg.hdr.version);
		goto out;
	}

	switch (msg.hdr.opcode & SSA_HEALTH_OP_MASK) {
	case SSA_HEALTH_NODE_TYPE:
		msg.data.node_type.type = SSA_NODE_CORE;
		ret = send(client->sock, (char *) &msg, msg.hdr.length, 0);
		if (ret != msg.hdr.length)
			goto out;
		break;
	case SSA_HEALTH_NODE_VERSION:
		snprintf(msg.data.node_version.version,
			 sizeof(msg.data.node_version.version),
			 "ibssa_1.0_kodiak");
		ret = send(client->sock, (char *) &msg, msg.hdr.length, 0);
		if (ret != msg.hdr.length)
			goto out;
		break;
	case SSA_HEALTH_UP_CONNS:
	case SSA_HEALTH_DOWN_CONNS:
	case SSA_HEALTH_UPDATES_NUM:
		break;
	default:
		printf("%s: ERROR - unknown opcode 0x%x\n", __func__, msg.hdr.opcode);
		break;
	}

	printf("%s: DEBUG: %d operation\n",
	       __func__, msg.hdr.opcode & SSA_HEALTH_OP_MASK);
out:
	if (ret)
		ssa_disconnect_client(client);
}

static void *ssa_server(void)
{
	struct pollfd **fds;
	struct pollfd *pfd;
	int i, ret, client_index, slot;

	printf("%s: started\n", __func__);
	ssa_init_server();
	ret = ssa_listen();
	if (ret) {
		printf("%s: ERROR - server listen failed\n", __func__);
		return;
	}

	fds = calloc(FD_SETSIZE, sizeof(**fds));
	if (!fds)
		goto out;

	pfd = (struct pollfd *)fds;
	pfd->fd = listen_socket;
	pfd->events = POLLIN;
	pfd->revents = 0;

	for (i = 1; i < FD_SETSIZE; i++) {
		pfd = (struct pollfd *)(fds + i);
		pfd->fd = -1; /* placeholder for client connections */
		pfd->events = 0;
		pfd->revents = 0;
	}

	for (;;) {
		ret = poll((struct pollfd *)fds, FD_SETSIZE, -1);
		if (ret < 0) {
			printf("%s: ERROR - server poll\n", __func__);
			continue;
		}

		pfd = (struct pollfd *)fds;
		if (pfd->revents) {
			pfd->revents = 0;
			client_index = ssa_svr_accept();
			if (client_index < 0)
				goto out;

			/* Indices correlation: client_index = fds_index - 1 */
			pfd = (struct pollfd *)(fds + client_index + 1);
			pfd->fd = client_array[client_index].sock;
			pfd->events = POLLIN;
			pfd->revents = 0;
		}

		for (i = 1; i < FD_SETSIZE; i++) {
			pfd = (struct pollfd *)(fds + i);
			if (pfd->revents) {
				if (pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
					/* close connection */
					client_array[i - 1].sock = -1;
					pfd->fd = -1;
					pfd->events = 0;
				} else {
					printf("%s: receiving from client %d\n", __func__, i - 1);
					ssa_svr_receive(&client_array[i - 1]);
				}
				pfd->revents = 0;
			}
		}
	}
out:
	if (fds)
		free(fds);

	return NULL;
}

int main()
{
	ssa_server();

	return 0;
}

