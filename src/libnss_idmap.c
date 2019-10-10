
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


#define FALSE 0
#define TRUE (!FALSE)

#define ZERO(x) do{memset(&x, 0, sizeof(x));}while(0)

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


/* we store gid_t in uid_t, hopefully they are not so different */
typedef uid_t id_t;

enum nssdb_type {
	NSSDB_PASSWD,
	NSSDB_GROUP,
};

enum mapping_interval {
	MAPINTV_N_TO_1,
	MAPINTV_N_TO_N,
};

struct idmapping {
	enum nssdb_type nssdb_type;
	id_t id_from_start;
	id_t id_from_end;
	id_t id_to;
	enum mapping_interval intv;
	struct idmapping *next;
};

// TODO: thread-safety

static int passthrough_mode;
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
	ssize_t pos;
	
	
	if(mappings_fh != NULL)
	{
		if(fstat(fileno(mappings_fh), &st) == -1) st.st_mtime = 0;
	}
	
	if(mappings_fh == NULL || (mappings_fh != NULL && st.st_mtime > mappings_mtime))
	{
		/* open/rewind file */
		
		if(mappings_fh == NULL)
		{
			mappings_fh = fopen("/etc/nss.d/idmap", "r");
		}
		else
		{
			fseek(mappings_fh, 0, 0);
		}
		
		if(mappings_fh != NULL)
		{
			if(fstat(fileno(mappings_fh), &st) == -1) st.st_mtime = 0;
			mappings_mtime = st.st_mtime;
			
			/* clear current mappings */
			for(p_map1 = idmappings; p_map1 != NULL; p_map1 = p_map2)
			{
				p_map2 = p_map1->next;
				free(p_map1);
			}
			idmappings = NULL;
			
			/* read mappings from file */
			while(!feof(mappings_fh))
			{
				ZERO(map);
				ZERO(nssdb_type_flag);
				ZERO(interval_type_flag);
				
				// TODO: filesystem-based uid/gid mapping
				
				pos = ftell(mappings_fh);
				
				if(fscanf(mappings_fh, "%1[ug]id %u-%u %u%1[-] \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to, interval_type_flag) == 5 ||
				   (fseek(mappings_fh, pos, 0)==0 && fscanf(mappings_fh, "%1[ug]id %u-%u %u \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to) == 4) ||
				   (fseek(mappings_fh, pos, 0)==0 && fscanf(mappings_fh, "%1[ug]id %u %u \n", nssdb_type_flag, &map.id_from_start, &map.id_to) == 3))
				{
					/* append this mapping */
					map.nssdb_type = nssdb_type_flag[0] == 'u' ? NSSDB_PASSWD : NSSDB_GROUP;
					map.intv = interval_type_flag[0] == '-' ? MAPINTV_N_TO_N : MAPINTV_N_TO_1;
					
					p_map2 = malloc(sizeof(struct idmapping));
					if(p_map2 == NULL) abort();
					if(idmappings == NULL) idmappings = p_map2;
					else p_map1->next = p_map2;
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

void do_idmap(enum nssdb_type nssdb_type, id_t *id)
{
	struct idmapping *p_map;
	
	read_idmap();
	
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
				
				if(p_map->intv == MAPINTV_N_TO_1)
					*id = p_map->id_to;
				else
					*id = p_map->id_to + (*id - p_map->id_from_start);
				
				#ifdef DEBUG
				printf(stderr, "to %d\n", *id);
				#endif
				
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

void do_idmap_pwd(struct passwd *pwd)
{
	do_idmap(NSSDB_PASSWD, (id_t*)&(pwd->pw_uid));
	do_idmap(NSSDB_GROUP, (id_t*)&(pwd->pw_gid));
}

void do_idmap_grp(struct group *grp)
{
	do_idmap(NSSDB_GROUP, (id_t*)&(grp->gr_gid));
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
		
		passthrough_mode = TRUE;
		error = getpwnam_r(name, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		do_idmap_pwd(result);
		
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
		
		lookup_uid = uid;
		do_idmap_reverse(NSSDB_PASSWD, (id_t*)&lookup_uid);
		
		if(lookup_uid == uid)
		{
			/* there is no uid mapped to the requested uid, 
			   check if the requested uid maps to something */
			do_idmap(NSSDB_PASSWD, (id_t*)&lookup_uid);
			if(lookup_uid != uid)
			{
				/* don't show this entry with the UID which has to be replaced */
				return NSS_STATUS_NOTFOUND;
			}
		}
		
		passthrough_mode = TRUE;
		error = getpwuid_r(lookup_uid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		result->pw_uid = uid;
		do_idmap(NSSDB_GROUP, (id_t*)&(result->pw_gid));
		
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
		
		passthrough_mode = TRUE;
		error = getgrnam_r(name, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		do_idmap_grp(result);
		
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
		
		lookup_gid = gid;
		do_idmap_reverse(NSSDB_GROUP, (id_t*)&lookup_gid);
		
		if(lookup_gid == gid)
		{
			/* there is no gid mapped to the requested gid, 
			   check if the requested gid maps to something */
			do_idmap(NSSDB_GROUP, (id_t*)&lookup_gid);
			if(lookup_gid != gid)
			{
				/* don't show this entry with the GID which has to be replaced */
				return NSS_STATUS_NOTFOUND;
			}
		}
		
		passthrough_mode = TRUE;
		error = getgrgid_r(lookup_gid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		result->gr_gid = gid;
		
		return NSS_STATUS_SUCCESS;
	}
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
}

enum nss_status
_nss_idmap_setpwent(int stayopen)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		struct passwd *pwd;
		struct passwd *pwent;
		unsigned int idx_entry;
		
		passthrough_mode = TRUE;
		free_pwentries();
		
		/* load shared library in a separate address space,
		   because in the main address space setXXent and getXXent are locked at this point */
		void *lib = dlmopen(LM_ID_NEWLM, "libc.so.6", RTLD_LAZY | RTLD_DEEPBIND);
		char *e = dlerror();
		if(e)
		{
			warnx("libnss_idmap: %s", e);
			passthrough_mode = FALSE;
			return NSS_STATUS_UNAVAIL;
		}
		void (* _setpwent)(void) = dlsym(lib, "setpwent");
		void (* _endpwent)(void) = dlsym(lib, "endpwent");
		struct passwd * (* _getpwent)(void) = dlsym(lib, "getpwent");
		
		_setpwent();
		
		/* load passwd entries */
		idx_entry = 0;
		while((pwd = _getpwent()) != NULL)
		{
			pwentries = realloc(pwentries, (idx_entry+2) * sizeof(struct passwd));
			if(pwentries == NULL) abort();
			
			/* copy over pwd to our static array */
			pwentries[idx_entry].pw_name = abstrdup(pwd->pw_name);
			pwentries[idx_entry].pw_passwd = abstrdup(pwd->pw_passwd);
			pwentries[idx_entry].pw_uid = pwd->pw_uid;
			pwentries[idx_entry].pw_gid = pwd->pw_gid;
			pwentries[idx_entry].pw_gecos = abstrdup(pwd->pw_gecos);
			pwentries[idx_entry].pw_dir = abstrdup(pwd->pw_dir);
			pwentries[idx_entry].pw_shell = abstrdup(pwd->pw_shell);
			
			idx_entry++;
			pwentries[idx_entry].pw_name = NULL;
		}
		
		cur_pwent = pwentries;
		_endpwent();
		dlclose(lib);
		
		passthrough_mode = FALSE;
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
_nss_idmap_endpwent()
{
	if(passthrough_mode)
		return NSS_STATUS_UNAVAIL;
	else
	{
		free_pwentries();
		return NSS_STATUS_SUCCESS;
	}
}

void fill_getent_buffer(char ** buffer, char ** dst, char * src)
{
	strcpy(*buffer, src);
	*dst = *buffer;
	*buffer += strlen(src)+1;
}

enum nss_status
_nss_idmap_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		if(cur_pwent == NULL || cur_pwent->pw_name == NULL)
			return NSS_STATUS_NOTFOUND;
		
		if(buflen < strlen(cur_pwent->pw_name)+1 + strlen(cur_pwent->pw_passwd)+1 + strlen(cur_pwent->pw_gecos)+1 + strlen(cur_pwent->pw_dir)+1 + strlen(cur_pwent->pw_shell)+1)
		{
			/* given buffer is too small */
			*errnop = ERANGE;
			return NSS_STATUS_TRYAGAIN;
		}
		
		char * bptr = buffer;
		
		fill_getent_buffer(&bptr, &(result->pw_name), cur_pwent->pw_name);
		fill_getent_buffer(&bptr, &(result->pw_passwd), cur_pwent->pw_passwd);
		fill_getent_buffer(&bptr, &(result->pw_gecos), cur_pwent->pw_gecos);
		fill_getent_buffer(&bptr, &(result->pw_dir), cur_pwent->pw_dir);
		fill_getent_buffer(&bptr, &(result->pw_shell), cur_pwent->pw_shell);
		result->pw_uid = cur_pwent->pw_uid;
		result->pw_gid = cur_pwent->pw_gid;
		
		do_idmap_pwd(result);
		
		/* move pointer forward */
		cur_pwent = &cur_pwent[1];
		
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
_nss_idmap_setgrent(int stayopen)
{
	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_idmap_endgrent()
{
	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_idmap_getgrent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	return NSS_STATUS_UNAVAIL;
}
