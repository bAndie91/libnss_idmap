
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

#define FALSE 0
#define TRUE (!FALSE)

#define ZERO(x) do{memset(&x, 0, sizeof(x));}while(0)

#define HANDLE_ERRORS_R if(result == NULL){\
		if(error == 0) return NSS_STATUS_NOTFOUND;\
		else { *errnop = error; return NSS_STATUS_UNAVAIL; } }

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
	
	// FIXME: uid=2000 gid=2000 groups=4294967295,4(adm),...
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
		
		passthrough_mode = TRUE;
		error = getgrgid_r(lookup_gid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		result->gr_gid = gid;
		
		return NSS_STATUS_SUCCESS;
	}
}

#if 0
enum nss_status
_nss_idmap_endpwent(void)
{
	if() return NSS_STATUS_UNAVAIL;
}

enum nss_status
_nss_idmap_setpwent(int stayopen)
{
	return (dir == NULL) ? NSS_STATUS_UNAVAIL : NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_idmap_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	char path[PATH_MAX], *line;
	struct dirent *ent;
	struct stat st;
	struct passwd structure;
	long offset;

	LOCK();

	/* If we don't have a current directory, try to reset. */
	if (dir == NULL) {
		setent(TRUE);
		/* If we couldn't open the directory, then we'd better just
		 * give up now. */
		if (dir == NULL) {
			UNLOCK();
			return NSS_STATUS_NOTFOUND;
		}
	}

	do {
		/* If we don't have a current file, try to open the next file
		 * in the directory. */
		if ((fp == NULL) || feof(fp)) {
			if (fp != NULL) {
				fclose(fp);
				fp = NULL;
			}

			do {
				/* Read the next entry in the directory. */
				ent = readdir(dir);
				if (ent == NULL) {
					closedir(dir);
					dir = NULL;
					continue;
				}

				/* If the file has a certain name, skip it. */
				if (skip_file_by_name(ent->d_name)) {
					continue;
				}

				/* Formulate the full path name and try to
				 * open it. */
				snprintf(path, sizeof(path),
					 SYSTEM_DATABASE_DIR "/"
					 DATABASE ".d/%s",
					 ent->d_name);
				fp = fopen(path, "r");

				/* If we failed to open the file, move on. */
				if (fp == NULL) {
					continue;
				}

				/* If we can't stat() the file, move on. */
				if (fstat(fileno(fp), &st) != 0) {
					fclose(fp);
					fp = NULL;
					continue;
				}

				/* If the file isn't normal or a symlink,
				 * move on. */
				if (!S_ISREG(st.st_mode) &&
				    !S_ISLNK(st.st_mode)) {
					fclose(fp);
					fp = NULL;
					continue;
				}
			} while ((dir != NULL) && (fp == NULL));
		}

		/* If we're out of data, return NOTFOUND. */
		if ((dir == NULL) || (fp == NULL)) {
			UNLOCK();
			return NSS_STATUS_NOTFOUND;
		}

		/* Read a line from the file. */
		offset = ftell(fp);
		line = read_line(fp);
		if (line == NULL) {
			fclose(fp);
			fp = NULL;
			continue;
		}

		/* Check that we have room to save this. */
		if (strlen(line) >= buflen) {
			free(line);
			fseek(fp, offset, SEEK_SET);
			errno = ERANGE;
			return NSS_STATUS_TRYAGAIN;
		}

		/* Try to parse the line. */
		strcpy(buffer, line);
		switch (parse_line(buffer, &structure,
				   (void *)buffer, buflen,
				   errnop)) {
		case -1:
			/* out of space */
			free(line);
			fseek(fp, offset, SEEK_SET);
			errno = ERANGE;
			return NSS_STATUS_TRYAGAIN;
			break;
		case 0:
			/* parse error (invalid format) */
			free(line);
			line = NULL;
			continue;
			break;
		case 1:
			/* success */
			free(line);
			*result = structure;
			UNLOCK();
			return NSS_STATUS_SUCCESS;
			break;
		default:
			break;
		}

		/* Try the next entry. */
		free(line);
		line = NULL;
	} while (1);

	/* We never really get here, but oh well. */
	UNLOCK();
	return NSS_STATUS_UNAVAIL;
}
#endif
