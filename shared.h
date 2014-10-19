#include <stdio.h>
#include <infiniband/sa.h>

#define SSA_HEALTH_VERSION		1

#define SSA_HEALTH_OP_MASK		0x0F
#define SSA_HEALTH_NODE_TYPE		0x01
#define SSA_HEALTH_NODE_VERSION		0x02
#define SSA_HEALTH_UP_CONNS		0x03
#define SSA_HEALTH_DOWN_CONNS		0x04
#define SSA_HEALTH_UPDATES_NUM		0x05
#define SSA_HEALTH_ACK			0x80

#define SSA_HEALTH_MSG_HDR_LEN		8
#define SSA_HEALTH_NODE_TYPE_LEN	8
#define SSA_HEALTH_NODE_VERSION_LEN	24
#define SSA_DTREE_NODE_DATA_LEN		8
#define SSA_DTREE_NODE_LEN		64

enum {
	SSA_NODE_CORE		= (1 << 0),
	SSA_NODE_DISTRIBUTION	= (1 << 1),
	SSA_NODE_ACCESS		= (1 << 2),
	SSA_NODE_CONSUMER	= (1 << 3)
};

struct msg_hdr {
	uint8_t                 version;
	uint8_t                 status;
	uint16_t                opcode;
	uint16_t                length;
	uint8_t			pad[2];
};

struct ssa_health_node_version {
	uint32_t		flags;
	uint8_t			version[20];
};

struct ssa_health_node_type {
	uint32_t		flags;
	uint8_t			type;
	uint8_t			reserved[3];
};

struct ssa_dtree_node {
	uint8_t                 name[64];
};

struct ssa_dtree_node_data {
	uint32_t                flags;
	uint16_t                node_num;
	uint8_t			reserved[2];
	struct ssa_dtree_node	nodes[0];
};

struct ssa_health_msg {
	struct msg_hdr                  hdr;
	union { /* not sure if union is a good idea */
		struct ssa_health_node_type	node_type;
		struct ssa_health_node_version	node_version;
		struct ssa_dtree_node_data	conn_data;
	} data;
};

/* Helper methods from SSA framework */
inline char *ssa_node_type_str(int node_type)
{
	switch (node_type) {
	case SSA_NODE_CORE:
		return "Core";
	case (SSA_NODE_CORE | SSA_NODE_ACCESS):
		return "Core + Access";
	case (SSA_NODE_DISTRIBUTION | SSA_NODE_ACCESS):
		return "Distribution + Access";
	case SSA_NODE_DISTRIBUTION:
		return "Distribution";
	case SSA_NODE_ACCESS:
		return "Access";
	case SSA_NODE_CONSUMER:
		return "Consumer";
	default:
		return "Other";
	}
}
