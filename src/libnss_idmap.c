
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>
#include <err.h>
#include <linux/limits.h>


#define FALSE 0
#define TRUE (!FALSE)

/* where to load secondary setXXent/getXXent/endXXent symbols from */
#define LIBC_NAME "libc.so.6"

#define ZERO(x) do{memset(&(x), 0, sizeof(x));}while(0)
#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

#define HANDLE_ERRORS_R if(result == NULL){\
		if(error == 0) return NSS_STATUS_NOTFOUND;\
		else { *errnop = error; return NSS_STATUS_UNAVAIL; } }

#define HANDLE_ERRORS_GETENT_R if(result == NULL){\
		*errnop = error;\
		if(error == ENOENT) return NSS_STATUS_NOTFOUND;\
		else return NSS_STATUS_UNAVAIL; }

char * abstrdup(const char *src)
{
	char *dst = strdup(src);
	if(dst == NULL) abort();
	return dst;
}

void * abmalloc(size_t size)
{
	void * p = malloc(size);
	if(p == NULL) abort();
	return p;
}

void abstrrepl(char ** str, const char * find, const char * repl)
{
	/* Replace all occurances of 'find' to 'repl' in string pointed by 'str'.
	   Replacement is not recursive.
	   '*str' must be allocated by malloc (realloc, calloc, strdup, etc...)
	   On memory allocation error, calls abort(3) */
	char *p;
	char *x;
	
	p = *str;
	
	while((p = strstr(p, find)) != NULL)
	{
		/* Allocate enough space to hold the new string */
		x = abmalloc(strlen(*str) - strlen(find) + strlen(repl) + 1);
		
		sprintf(x, "%.*s%s%s", p - *str, *str, repl, p + strlen(find));
		
		/* Let 'p' point to the next char after the replaced substring */
		p = (char*)((int)p + strlen(repl) + (int)x - (int)*str);
		free(*str);
		*str = x;
	}
}

unsigned int n_digits(unsigned int i)
{
	/* most UIDs are 0-5 digits, so check them first */
	if(i < 100000)
	{
		if(i >= 10000) return 5;
		if(i >= 1000) return 4;
		if(i >= 100) return 3;
		if(i >= 10) return 2;
		return 1;
	}
	/* then come the extreme cases */
	if(i >= 10000000000000000000U) abort(); /* does not support numbers more than 19 digits */
	if(i >= 1000000000000000000) return 19;
	if(i >= 100000000000000000) return 18;
	if(i >= 10000000000000000) return 17;
	if(i >= 1000000000000000) return 16;
	if(i >= 100000000000000) return 15;
	if(i >= 10000000000000) return 14;
	if(i >= 1000000000000) return 13;
	if(i >= 100000000000) return 12;
	if(i >= 10000000000) return 11;
	if(i >= 1000000000) return 10;
	if(i >= 100000000) return 9;
	if(i >= 10000000) return 8;
	if(i >= 1000000) return 7;
	return 6;
}


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
	id_t id_to;
	enum mapping_interval intv;
	bool hide;
	char *statpath;
	enum stat_error_behave on_stat_error;
	struct idmapping *next;
};

// TODO: thread-safety

static bool passthrough_mode;
static FILE *mappings_fh;
static time_t mappings_mtime;
static struct idmapping *idmappings;
static char *mappings_file = "/etc/nss.d/idmap";
static struct passwd *pwentries;
static struct passwd *cur_pwent;
static struct group *grentries;
static struct group *cur_grent;


void read_idmap()
{
	struct stat st;
	struct idmapping map;
	struct idmapping *p_map1;
	struct idmapping *p_map2;
	char nssdb_type_flag[2];
	char interval_type_flag[2];
	char hide_flag[2];
	char cbuf[2];
	char pbuf[PATH_MAX+1];
	ssize_t pos;
	
	
	if(mappings_fh != NULL)
	{
		if(fstat(fileno(mappings_fh), &st) == -1) st.st_mtime = 0;
	}
	
	if(mappings_fh == NULL || (mappings_fh != NULL && st.st_mtime > mappings_mtime))
	{
		/* open/rewind file */
		
		if(mappings_fh == NULL)
			mappings_fh = fopen("/etc/nss.d/idmap", "r");
		else
			fseek(mappings_fh, 0, 0);
		
		if(mappings_fh != NULL)
		{
			if(fstat(fileno(mappings_fh), &st) == -1)
			{
				st.st_mtime = 0;
				st.st_size = 0;
			}
			mappings_mtime = st.st_mtime;
			
			/* clear current mappings */
			for(p_map1 = idmappings; p_map1 != NULL; p_map1 = p_map2)
			{
				p_map2 = p_map1->next;
				free(p_map1->statpath);
				free(p_map1);
			}
			idmappings = NULL;
			
			/* read mappings from file */
			while(!feof(mappings_fh))
			{
				ZERO(map);
				ZERO(nssdb_type_flag);
				ZERO(interval_type_flag);
				ZERO(hide_flag);
				ZERO(cbuf);
				ZERO(pbuf);
				
				// TODO: map by user/group name
				
				pos = ftell(mappings_fh);
				if(st.st_size != 0 && pos >= st.st_size) break;
				#define REWIND (fseek(mappings_fh, pos, 0)==0)
				
				if((REWIND && fscanf(mappings_fh, "%1[#]%*[^\n]%1[\n]", cbuf, cbuf) == 2) ||
				   (REWIND && fscanf(mappings_fh, "%1[#]%1[\n]", cbuf, cbuf) == 2) ||
				   (REWIND && fscanf(mappings_fh, "%1[\n]", cbuf) == 1))
					continue;
				
				if((REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u %u%1[-] \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to, interval_type_flag) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u %1[-] \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, hide_flag) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u %u \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u %1[-] \n", nssdb_type_flag, &map.id_from_start, hide_flag) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u %u \n", nssdb_type_flag, &map.id_from_start, &map.id_to) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4))
				{
					/* append this mapping */
					map.nssdb_type = nssdb_type_flag[0] == 'u' ? NSSDB_PASSWD : NSSDB_GROUP;
					map.intv = interval_type_flag[0] == '-' ? MAPINTV_N_TO_N : MAPINTV_N_TO_1;
					map.hide = hide_flag[0] == '\0' ? FALSE : TRUE;
					
					p_map2 = abmalloc(sizeof(struct idmapping));
					if(idmappings == NULL) idmappings = p_map2;
					else p_map1->next = p_map2;
					
					if(pbuf[0] != '\0')
					{
						map.statpath = abstrdup(pbuf);
						switch(cbuf[0])
						{
							case 'h': map.on_stat_error = STATERR_HIDE; break;
							case 'r': map.on_stat_error = STATERR_RETAIN; break;
							case 'i': map.on_stat_error = STATERR_IGNORE; break;
						}
					}
					memcpy(p_map2, &map, sizeof(struct idmapping));
					p_map1 = p_map2;
				}
				else
				{
					warnx("libnss_idmap: %s: invalid config beginning at offset %d", mappings_file, pos);
					/* discard current line */
					fscanf(mappings_fh, "%*[^\n]\n");
				}
			}
		}
	}
}

void do_idmap(enum nssdb_type nssdb_type, id_t *id, const char *name, bool *hide)
{
	struct idmapping *p_map;
	struct stat st;
	char *path;
	char *id_str;
	bool pt_mode;
	struct passwd *lazy_pwd;
	struct group *lazy_grp;
	
	read_idmap();
	if(hide != NULL) *hide = FALSE;
	
	for(p_map = idmappings; p_map != NULL; p_map = p_map->next)
	{
		if(p_map->nssdb_type == nssdb_type)
		{
			if((p_map->id_from_start <= *id && p_map->id_from_end >= *id) ||
			   (p_map->id_from_start == *id && p_map->id_from_end == 0))
			{
				#ifdef DEBUG
				printf(stderr, "libnss_idmap: forward map %cid %d ", nssdb_type == NSSDB_PASSWD ? 'u' : 'g', *id);
				#endif
				
				if(p_map->statpath != NULL)
				{
					path = abstrdup(p_map->statpath);
					id_str = abmalloc(n_digits(*id) + 1);
					sprintf(id_str, "%u", *id);
					abstrrepl(&path, "{ID}", id_str);
					free(id_str);
					if(strstr(path, "{NAME}") != NULL && name == NULL)
					{
						/* 'name' was not known by caller, let's find it now */
						pt_mode = passthrough_mode;
						passthrough_mode = TRUE;
						if(nssdb_type == NSSDB_PASSWD)
						{
							lazy_pwd = getpwuid(*id);
							if(lazy_pwd != NULL)
								name = lazy_pwd->pw_name;
						}
						else
						{
							lazy_grp = getgrgid(*id);
							if(lazy_grp != NULL)
								name = lazy_grp->gr_name;
						}
						passthrough_mode = pt_mode;
						
						if(name == NULL)
						{
							/* Entry (actually a group, because name is always given 
							   for NSSDB_PASSWD calls) was not found, but entry name
							   is needed to construct file name. So treat it like
							   stat(2) errors. */
							goto stat_path_error;
						}
					}
					abstrrepl(&path, "{NAME}", name);
					
					if(stat(path, &st) == 0)
					{
						*id = nssdb_type == NSSDB_PASSWD ? st.st_uid : st.st_gid;
					}
					else
					{
						stat_path_error:
						if(p_map->on_stat_error == STATERR_HIDE)
						{
							if(hide != NULL) *hide = TRUE;
						}
						else if(p_map->on_stat_error == STATERR_IGNORE)
						{
							free(path);
							continue;
						}
					}
					free(path);
				}
				else if(p_map->hide)
				{
					if(hide != NULL) *hide = TRUE;
					
					#ifdef DEBUG
					printf(stderr, "to -\n");
					#endif
				}
				else
				{
					if(p_map->intv == MAPINTV_N_TO_1)
						*id = p_map->id_to;
					else
						*id = p_map->id_to + (*id - p_map->id_from_start);
					
					#ifdef DEBUG
					printf(stderr, "to %d\n", *id);
					#endif
				}
				break;
			}
		}
	}
}

void do_idmap_reverse(enum nssdb_type nssdb_type, id_t *id)
{
	struct idmapping *p_map;
	
	read_idmap();
	
	for(p_map = idmappings; p_map != NULL; p_map = p_map->next)
	{
		if(p_map->nssdb_type == nssdb_type)
		{
			if((p_map->intv == MAPINTV_N_TO_1 && p_map->id_to == *id) ||
			   (p_map->intv == MAPINTV_N_TO_N && p_map->id_to <= *id && (p_map->id_to + (p_map->id_from_end - p_map->id_from_start)) >= *id))
			{
				#ifdef DEBUG
				printf(stderr, "libnss_idmap: reverse map %cid %d ", nssdb_type == NSSDB_PASSWD ? 'u' : 'g', *id);
				#endif
				
				if(p_map->intv == MAPINTV_N_TO_1)
					/* NOTE: ambiguous reverse mapping */
					*id = p_map->id_from_start;
				else
					*id = p_map->id_from_start + (*id - p_map->id_to);
				
				#ifdef DEBUG
				printf(stderr, "to %d\n", *id);
				#endif
				
				break;
			}
		}
	}
}

void do_idmap_pwd(struct passwd *pwd, bool *hide)
{
	do_idmap(NSSDB_PASSWD, (id_t*)&(pwd->pw_uid), pwd->pw_name, hide);
	do_idmap(NSSDB_GROUP, (id_t*)&(pwd->pw_gid), NULL, NULL);
}

void do_idmap_grp(struct group *grp, bool *hide)
{
	do_idmap(NSSDB_GROUP, (id_t*)&(grp->gr_gid), grp->gr_name, hide);
}



enum nss_status
_nss_idmap_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		int error;
		bool hide;
		
		passthrough_mode = TRUE;
		error = getpwnam_r(name, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		do_idmap_pwd(result, &hide);
		if(hide) return NSS_STATUS_NOTFOUND;
		
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
_nss_idmap_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		int error;
		uid_t lookup_uid;
		bool hide;
		
		/* lookup which UID would map to the requested UID 
		   and get that one from the upstream modules */
		lookup_uid = uid;
		do_idmap_reverse(NSSDB_PASSWD, (id_t*)&lookup_uid);
		
		if(lookup_uid == uid)
		{
			/* there is no UID mapped to the requested UID,
			   check if the requested UID maps to something else */
			do_idmap(NSSDB_PASSWD, (id_t*)&lookup_uid, NULL, &hide); // TODO: pw_name
			if(lookup_uid != uid || hide)
			{
				/* don't show this entry, because it has an UID 
				   which has to be replaced or hidden */
				return NSS_STATUS_NOTFOUND;
			}
		}
		
		passthrough_mode = TRUE;
		error = getpwuid_r(lookup_uid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		/* Note: you won't necessarily get back the requested UID
		   if you defined N:1 mapping to the requested UID. */
		do_idmap_pwd(result, &hide);
		if(hide) return NSS_STATUS_NOTFOUND;
		
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
_nss_idmap_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		int error;
		bool hide;
		
		passthrough_mode = TRUE;
		error = getgrnam_r(name, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		do_idmap_grp(result, &hide);
		if(hide) return NSS_STATUS_NOTFOUND;
		
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
_nss_idmap_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		int error;
		gid_t lookup_gid;
		bool hide;
		
		/* perform reverse mapping.
		   see comments in _nss_idmap_getpwuid_r(). */
		lookup_gid = gid;
		do_idmap_reverse(NSSDB_GROUP, (id_t*)&lookup_gid);
		
		if(lookup_gid == gid)
		{
			do_idmap(NSSDB_GROUP, (id_t*)&lookup_gid, NULL, &hide); // TODO: gr_name
			if(lookup_gid != gid || hide)
			{
				return NSS_STATUS_NOTFOUND;
			}
		}
		
		passthrough_mode = TRUE;
		error = getgrgid_r(lookup_gid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		do_idmap_grp(result, &hide);
		if(hide) return NSS_STATUS_NOTFOUND;
		
		return NSS_STATUS_SUCCESS;
	}
}

void copy_pwent(struct passwd *dst, struct passwd *src)
{
	/* copy over pwd to our static array */
	dst->pw_name = abstrdup(src->pw_name);
	dst->pw_passwd = abstrdup(src->pw_passwd);
	dst->pw_uid = src->pw_uid;
	dst->pw_gid = src->pw_gid;
	dst->pw_gecos = abstrdup(src->pw_gecos);
	dst->pw_dir = abstrdup(src->pw_dir);
	dst->pw_shell = abstrdup(src->pw_shell);
}

void copy_grent(struct group *dst, struct group *src)
{
	/* copy over grp to our static array */
	unsigned int idx_mem;
	
	dst->gr_name = abstrdup(src->gr_name);
	dst->gr_passwd = abstrdup(src->gr_passwd);
	dst->gr_gid = src->gr_gid;
	
	dst->gr_mem = abmalloc(sizeof(void*));
	for(idx_mem = 0; src->gr_mem != NULL && src->gr_mem[idx_mem] != NULL; idx_mem++)
	{
		dst->gr_mem = realloc(dst->gr_mem, (idx_mem+2) * sizeof(void*));
		if(dst->gr_mem == NULL) abort();
		dst->gr_mem[idx_mem] = abstrdup(src->gr_mem[idx_mem]);
	}
	dst->gr_mem[idx_mem] = NULL;
}

void free_pwentries()
{
	unsigned int idx_entry;
	for(idx_entry = 0; pwentries != NULL && pwentries[idx_entry].pw_name != NULL; idx_entry++)
	{
		free(pwentries[idx_entry].pw_name);
		free(pwentries[idx_entry].pw_passwd);
		free(pwentries[idx_entry].pw_gecos);
		free(pwentries[idx_entry].pw_dir);
		free(pwentries[idx_entry].pw_shell);
	}
	free(pwentries);
	pwentries = NULL;
}

void free_grentries()
{
	unsigned int idx_entry, idx_mem;
	for(idx_entry = 0; grentries != NULL && grentries[idx_entry].gr_name != NULL; idx_entry++)
	{
		for(idx_mem = 0; grentries[idx_entry].gr_mem != NULL && grentries[idx_entry].gr_mem[idx_mem] != NULL; idx_mem++)
			free(grentries[idx_entry].gr_mem[idx_mem]);
		free(grentries[idx_entry].gr_mem);
		free(grentries[idx_entry].gr_passwd);
		free(grentries[idx_entry].gr_name);
	}
	free(grentries);
	grentries = NULL;
}

size_t sizeof_passwd(struct passwd *pwent)
{
	/* return the minimum buffer size which can hold all the strings in the given passwd struct */
	return strlen(pwent->pw_name)+1 
	  + strlen(pwent->pw_passwd)+1 
	  + strlen(pwent->pw_gecos)+1 
	  + strlen(pwent->pw_dir)+1 
	  + strlen(pwent->pw_shell)+1;
}

size_t sizeof_group(struct group *grent)
{
	/* return the minimum buffer size which can hold all the strings in the given group struct */
	size_t size_members;
	unsigned int idx_mem;
	
	size_members = 0;
	for(idx_mem = 0; grent->gr_mem != NULL && grent->gr_mem[idx_mem] != NULL; idx_mem++)
		size_members += sizeof(void*) + strlen(grent->gr_mem[idx_mem]) + 1;
	
	return strlen(grent->gr_name)+1 
	  + strlen(grent->gr_passwd)+1
	  + size_members;
}

void fill_getent_buffer(char ** buffer, char ** dst, char * src)
{
	/* copy src into buffer,
	   point dst to the copy,
	   move buffer pointer to the remaining free space.
	   check buffer size in prior. */
	strcpy(*buffer, src);
	if(dst != NULL) *dst = *buffer;
	*buffer += strlen(src)+1;
}

void copy_passwd_to_result(char * buffer, struct passwd * result, struct passwd *pwent)
{
	char * bptr = buffer;
	
	fill_getent_buffer(&bptr, &(result->pw_name), pwent->pw_name);
	fill_getent_buffer(&bptr, &(result->pw_passwd), pwent->pw_passwd);
	fill_getent_buffer(&bptr, &(result->pw_gecos), pwent->pw_gecos);
	fill_getent_buffer(&bptr, &(result->pw_dir), pwent->pw_dir);
	fill_getent_buffer(&bptr, &(result->pw_shell), pwent->pw_shell);
	result->pw_uid = pwent->pw_uid;
	result->pw_gid = pwent->pw_gid;
}

void copy_group_to_result(char * buffer, struct group * result, struct group *grent)
{
	char * buf_ptr = buffer;
	unsigned int idx_mem;
	char * mem_ptr;
	
	fill_getent_buffer(&buf_ptr, &(result->gr_name), grent->gr_name);
	fill_getent_buffer(&buf_ptr, &(result->gr_passwd), grent->gr_passwd);
	result->gr_gid = grent->gr_gid;
	mem_ptr = buf_ptr;
	for(idx_mem = 0; grent->gr_mem != NULL && grent->gr_mem[idx_mem] != NULL; idx_mem++)
	{
		fill_getent_buffer(&buf_ptr, NULL, grent->gr_mem[idx_mem]);
	}
	result->gr_mem = (char**)buf_ptr;
	for(idx_mem = 0; grent->gr_mem != NULL && grent->gr_mem[idx_mem] != NULL; idx_mem++)
	{
		result->gr_mem[idx_mem] = mem_ptr;
		mem_ptr = (char*)(mem_ptr + strlen(mem_ptr) + 1);
	}
	result->gr_mem[idx_mem] = NULL;
}


#define STRUCTNAME struct passwd
#define FREE_ENTRIES free_pwentries
#define SETENTNAME "setpwent"
#define ENDENTNAME "endpwent"
#define GETENTNAME "getpwent"
#define IDMAP_SETENT _nss_idmap_setpwent
#define IDMAP_ENDENT _nss_idmap_endpwent
#define IDMAP_GETENT _nss_idmap_getpwent_r
#define COPY_STRUCT copy_pwent
#define GETENT_ARRAY pwentries
#define GETENT_POINTER cur_pwent
#define GETENT_NAME pw_name
#define DO_IDMAP do_idmap_pwd
#define SIZEOF_ENTRY sizeof_passwd
#define COPY_TO_RESULT copy_passwd_to_result

#include "getent.c"

#include "undef.c"

#define STRUCTNAME struct group
#define FREE_ENTRIES free_grentries
#define SETENTNAME "setgrent"
#define ENDENTNAME "endgrent"
#define GETENTNAME "getgrent"
#define IDMAP_SETENT _nss_idmap_setgrent
#define IDMAP_ENDENT _nss_idmap_endgrent
#define IDMAP_GETENT _nss_idmap_getgrent_r
#define COPY_STRUCT copy_grent
#define GETENT_ARRAY grentries
#define GETENT_POINTER cur_grent
#define GETENT_NAME gr_name
#define DO_IDMAP do_idmap_grp
#define SIZEOF_ENTRY sizeof_group
#define COPY_TO_RESULT copy_group_to_result

#include "getent.c"
