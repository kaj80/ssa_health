#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
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

static void ssa_svr_accept(void)
{
	int s, i;

	printf("%s\n", __func__);
	s = accept(listen_socket, NULL, NULL);
	if (s == -1) {
		printf("%s: ERROR - failed to accept connection\n", __func__ );
		return;
	}

	for (i = 0; i < FD_SETSIZE - 1; i++) {
		//if (!atomic_get(&client_array[i].refcnt))
		if (client_array[i].sock == -1)
			break;
	}

	if (i == FD_SETSIZE - 1) {
		printf("%s: ERROR - all connections busy - rejecting\n", __func__);
		close(s);
		return;
	}

	client_array[i].sock = s;
	//atomic_set(&client_array[i].refcnt, 1);
	printf("%s: assigned client %d\n", __func__, i);
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

static void ssa_server(void)
{
	fd_set readfds;
	int i, n, ret;

	printf("%s: started\n", __func__);
	ssa_init_server();
	ret = ssa_listen();
	if (ret) {
		printf("%s: ERROR - server listen failed\n", __func__);
		return;
	}

	while (1) {
		n = (int) listen_socket;
		FD_ZERO(&readfds);
		FD_SET(listen_socket, &readfds);

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1) {
				FD_SET(client_array[i].sock, &readfds);
				n = max(n, (int) client_array[i].sock);
			}
		}

		ret = select(n + 1, &readfds, NULL, NULL, NULL);
		if (ret == -1) {
			printf("%s: ERROR - server select error\n", __func__);
			continue;
		}

		if (FD_ISSET(listen_socket, &readfds))
			ssa_svr_accept();

		for (i = 0; i < FD_SETSIZE - 1; i++) {
			if (client_array[i].sock != -1 &&
				FD_ISSET(client_array[i].sock, &readfds)) {
				printf("%s: receiving from client %d\n", __func__, i);
				ssa_svr_receive(&client_array[i]);
			}
		}
	}
}

int main()
{
	ssa_server();

	return 0;
}

