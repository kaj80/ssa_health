#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <infiniband/sa.h>
#include "shared.h"

#define  HEALTH_QUERY_NODE_TYPE		(1 << 0)
#define  HEALTH_QUERY_NODE_VERSION	(1 << 1)
#define  HEALTH_QUERY_UP_NODES		(1 << 2)
#define  HEALTH_QUERY_DOWN_NODES	(1 << 3)
#define  HEALTH_QUERY_UPDATES_NUM	(1 << 4)

static int query_type;
static short server_port = 7125;
int sock = -1;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void show_usage(char *program)
{
	printf("%s usage:\n", program);
	printf("Query specified ssa health service for data\n");
	printf("   [-t] - query node type\n");
	printf("   [-v] - query node version\n");
	printf("   [-u] - query node for upstream connections\n");
	printf("   [-d] - query node for downstream connections\n");
}

static void ssa_set_server_port(void)
{
	FILE *f;

	if ((f = fopen("/var/run/ssa_health.port", "r"))) {
		fscanf(f, "%hu", (unsigned short *) &server_port);
		fclose(f);
	}
}

/* static void show_path(struct ibv_path_record *path)
{
	char gid[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	uint32_t fl_hop;

	printf("Path information\n");
	inet_ntop(AF_INET6, path->dgid.raw, gid, sizeof gid);
	printf("  dgid: %s\n", gid);
	inet_ntop(AF_INET6, path->sgid.raw, gid, sizeof gid);
	printf("  sgid: %s\n", gid);
	printf("  dlid: %u\n", ntohs(path->dlid));
	printf("  slid: %u\n", ntohs(path->slid));
	fl_hop = ntohl(path->flowlabel_hoplimit);
	printf("  flow label: 0x%x\n", fl_hop >> 8);
	printf("  hop limit: %d\n", (uint8_t) fl_hop);
	printf("  tclass: %d\n", path->tclass);
	printf("  reversible: %d\n", path->reversible_numpath >> 7);
	printf("  pkey: 0x%x\n", ntohs(path->pkey));
	printf("  sl: %d\n", ntohs(path->qosclass_sl) & 0xF);
	printf("  mtu: %d\n", path->mtu & 0x3F);
	printf("  rate: %d\n", path->rate & 0x3F);
	printf("  packet lifetime: %d\n", path->packetlifetime & 0x3F);
} */

static uint32_t get_query_flags()
{
	uint32_t flags = 0;

	//if (nodelay)
	//	flags |= ACM_FLAGS_NODELAY;

	return flags;
}

static int query_node_type()
{
	struct ssa_health_msg msg;
	struct ssa_health_node_type node_type;
	int ret;

	pthread_mutex_lock(&lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = SSA_HEALTH_VERSION;
	msg.hdr.opcode = SSA_HEALTH_NODE_TYPE;
	msg.hdr.length = SSA_HEALTH_MSG_HDR_LEN + SSA_HEALTH_NODE_TYPE_LEN;

	//data = &msg.data.node_type;
	//data->flags = flags;
	//data->type = ACM_EP_INFO_PATH;

	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < SSA_HEALTH_MSG_HDR_LEN || ret != msg.hdr.length) {
		printf("%s: ERROR - unable to query node type\n");
		goto out;
	}

	if (msg.hdr.status) {
		printf("ERROR - received ssa health msg with status %d\n",
		       msg.hdr.status);
		goto out;
	}

	node_type = msg.data.node_type;
	printf("%s: node type: %s\n", __func__, ssa_node_type_str(node_type.type));

out:
	pthread_mutex_unlock(&lock);
	return ret;
}

static int query_node_version()
{
	struct ssa_health_msg msg;
	struct ssa_health_node_version node_version;
	int ret;

	pthread_mutex_lock(&lock);
	memset(&msg, 0, sizeof msg);
	msg.hdr.version = SSA_HEALTH_VERSION;
	msg.hdr.opcode = SSA_HEALTH_NODE_VERSION;
	msg.hdr.length = SSA_HEALTH_MSG_HDR_LEN + SSA_HEALTH_NODE_VERSION_LEN;

	//data = &msg.data.node_type;
	//data->flags = flags;
	//data->type = ACM_EP_INFO_PATH;

	ret = send(sock, (char *) &msg, msg.hdr.length, 0);
	if (ret != msg.hdr.length)
		goto out;

	ret = recv(sock, (char *) &msg, sizeof msg, 0);
	if (ret < SSA_HEALTH_MSG_HDR_LEN || ret != msg.hdr.length) {
		printf("%s: ERROR - unable to query node version\n", __func__);
		goto out;
	}

	if (msg.hdr.status) {
		printf("ERROR - received ssa health msg with status %d\n",
		       msg.hdr.status);
		goto out;
	}

	node_version = msg.data.node_version;
	printf("%s: node version: %s\n", __func__, (char *) node_version.version);

out:
	pthread_mutex_unlock(&lock);
	return ret;
}

static int query()
{
	int ret;

	if (query_type & HEALTH_QUERY_NODE_TYPE)
		query_node_type();

	if (query_type & HEALTH_QUERY_NODE_VERSION)
		query_node_version();

	if ((query_type & HEALTH_QUERY_UP_NODES) ||
	    (query_type & HEALTH_QUERY_DOWN_NODES) ||
	    (query_type & HEALTH_QUERY_UPDATES_NUM))
		printf("%s: WARNING - unsupported queries were specified\n",
		       __func__);

out:
	return ret;
}

int ib_ssa_connect(char *dest)
{
	struct addrinfo hint, *res;
	int ret;

	ssa_set_server_port();
	memset(&hint, 0, sizeof hint);
	hint.ai_family = AF_INET;
	hint.ai_protocol = IPPROTO_TCP;
	ret = getaddrinfo(dest, NULL, &hint, &res);
	if (ret)
		return ret;

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
		ret = errno;
		goto err1;
	}

	((struct sockaddr_in *) res->ai_addr)->sin_port = htons(server_port);
	ret = connect(sock, res->ai_addr, res->ai_addrlen);
	if (ret)
		goto err2;

	freeaddrinfo(res);
	return 0;

err2:
	close(sock);
	sock = -1;
err1:
	freeaddrinfo(res);
	return ret;
}

void ib_ssa_disconnect(void)
{
	if (sock != -1) {
		shutdown(sock, SHUT_RDWR);
		close(sock);
		sock = -1;
	}
}

static int query_issue(void)
{
	char *dest = "localhost";
	int ret;

	ret = ib_ssa_connect(dest);
	if (ret) {
		printf("%s,unable to contact service: %s\n",
			dest, strerror(errno));
		goto out;
	}

	ret = query();
	if (ret) {
		ib_ssa_disconnect();
		goto out;
	}

	ib_ssa_disconnect();

out:
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret = 0;

	while ((op = getopt(argc, argv, "tvudhs")) != -1) {
		switch (op) {
		case 't':
			query_type |= HEALTH_QUERY_NODE_TYPE;
			break;
		case 'v':
			query_type |= HEALTH_QUERY_NODE_VERSION;
			break;
		case 'u':
			query_type |= HEALTH_QUERY_UP_NODES;
			break;
		case 'd':
			query_type |= HEALTH_QUERY_DOWN_NODES;
			break;
		case 's':
			query_type |= HEALTH_QUERY_UPDATES_NUM;
			break;
		case 'h':
		default:
			goto show_use;
		}
	}

	if (argc <= 1)
		goto show_use;

	ret = query_issue();

	return ret;

show_use:
	show_usage(argv[0]);
	exit(1);
}
