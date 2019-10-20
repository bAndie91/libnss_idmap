
/* we store gid_t in uid_t, hopefully they are not so different */
typedef uid_t id_t;

typedef char bool;

enum nssdb_type {
	NSSDB_PASSWD,
	NSSDB_GROUP,
};

enum mapping_interval {
	MAPINTV_N_TO_1,
	MAPINTV_N_TO_N,
};

enum stat_error_behave {
	STATERR_HIDE,
	STATERR_RETAIN,
	STATERR_IGNORE,
};

struct idmapping {
	enum nssdb_type nssdb_type;
	id_t id_from_start;
	id_t id_from_end;
	char *name_from;
	id_t id_to;
	enum mapping_interval intv;
	bool hide;
	char *statpath;
	enum stat_error_behave on_stat_error;
	struct idmapping *next;
};
