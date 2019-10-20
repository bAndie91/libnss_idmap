
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
#include <glob.h>


#define FALSE 0
#define TRUE (!FALSE)

/* where to load secondary setXXent/getXXent/endXXent symbols from */
#define LIBC_NAME "libc.so.6"

/* user/group name limit in config file */
#define ENTRYNAME_MAX 64

#define ZERO(x) do{memset(&(x), 0, sizeof(x));}while(0)
#define STRINGIFY(x) #x
#define STR(x) STRINGIFY(x)

#ifdef DEBUG
#define DODEBUG 1
#else
#define DODEBUG 0
#endif
#define DEBUGPRINT(...) do{if(DODEBUG){fprintf(stderr, __VA_ARGS__);};}while(0)

#define NSSDB_TYPE_CHAR (nssdb_type == NSSDB_PASSWD ? 'u' : 'g')

#define HANDLE_ERRORS_R if(result == NULL){\
		if(error == 0) return NSS_STATUS_NOTFOUND;\
		else { *errnop = error; return NSS_STATUS_UNAVAIL; } }

#define HANDLE_ERRORS_GETENT_R if(result == NULL){\
		*errnop = error;\
		if(error == ENOENT) return NSS_STATUS_NOTFOUND;\
		else return NSS_STATUS_UNAVAIL; }


#include "types.c"

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


#include "mem.c"
#include "xxent.c"
#include "intlookup.c"
#include "reent_buf.c"


void read_idmap()
{
	/* Read config file which contains ID mapping rules.
	   Fill up static space pointed by 'idmappings'.
	   Left file open.
	   Re-reads file only if changed (based on inode mtime). */
	struct stat st;
	struct idmapping map;
	struct idmapping *p_map1;
	struct idmapping *p_map2;
	char nssdb_type_flag[2];
	char interval_type_flag[2];
	char hide_flag[2];
	char cbuf[2];
	char pbuf[PATH_MAX+1];
	char name[ENTRYNAME_MAX+1];
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
				free(p_map1->name_from);
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
				ZERO(name);
				
				pos = ftell(mappings_fh);
				if(st.st_size != 0 && pos >= st.st_size) break;
				#define REWIND (fseek(mappings_fh, pos, 0)==0)
				
				/* skip comment and empty lines */
				if((REWIND && fscanf(mappings_fh, "%1[#]%*[^\n]%1[\n]", cbuf, cbuf) == 2) ||
				   (REWIND && fscanf(mappings_fh, "%1[#]%1[\n]", cbuf, cbuf) == 2) ||
				   (REWIND && fscanf(mappings_fh, "%1[\n]", cbuf) == 1))
					continue;
				
				if((REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u to %u%1[-] \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to, interval_type_flag) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u to %u \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, &map.id_to) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u %1[h]ide \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, hide_flag) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u-%u as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, &map.id_from_start, &map.id_from_end, pbuf, cbuf) == 5) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u to %u \n", nssdb_type_flag, &map.id_from_start, &map.id_to) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u %1[h]ide \n", nssdb_type_flag, &map.id_from_start, hide_flag) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[ug]id %u as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, &map.id_from_start, pbuf, cbuf) == 4) ||
				   
				   (REWIND && fscanf(mappings_fh, "%1[u]ser %"STR(ENTRYNAME_MAX)"s to %u \n", nssdb_type_flag, name, &map.id_to) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[g]roup %"STR(ENTRYNAME_MAX)"s to %u \n", nssdb_type_flag, name, &map.id_to) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[u]ser %"STR(ENTRYNAME_MAX)"s %1[h]ide \n", nssdb_type_flag, name, hide_flag) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[g]roup %"STR(ENTRYNAME_MAX)"s %1[h]ide \n", nssdb_type_flag, name, hide_flag) == 3) ||
				   (REWIND && fscanf(mappings_fh, "%1[u]ser %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, name, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[g]roup %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[h]ide \n", nssdb_type_flag, name, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[u]ser %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, name, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[g]roup %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[r]etain \n", nssdb_type_flag, name, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[u]ser %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, name, pbuf, cbuf) == 4) ||
				   (REWIND && fscanf(mappings_fh, "%1[g]roup %"STR(ENTRYNAME_MAX)"s as %"STR(PATH_MAX)"s or %1[i]gnore \n", nssdb_type_flag, name, pbuf, cbuf) == 4))
				{
					/* append this mapping */
					map.nssdb_type = nssdb_type_flag[0] == 'u' ? NSSDB_PASSWD : NSSDB_GROUP;
					map.intv = interval_type_flag[0] == '-' ? MAPINTV_N_TO_N : MAPINTV_N_TO_1;
					map.hide = hide_flag[0] != '\0' ? TRUE : FALSE;
					
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
					if(name[0] != '\0')
					{
						map.name_from = abstrdup(name);
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

void free_pwentries()
{
	unsigned int idx_entry;
	for(idx_entry = 0; pwentries != NULL && pwentries[idx_entry].pw_name != NULL; idx_entry++)
		free_pwentry_fields(&pwentries[idx_entry]);
	free(pwentries);
	pwentries = NULL;
}

void free_grentries()
{
	unsigned int idx_entry;
	for(idx_entry = 0; grentries != NULL && grentries[idx_entry].gr_name != NULL; idx_entry++)
		free_grentry_fields(&grentries[idx_entry]);
	free(grentries);
	grentries = NULL;
}

void do_idmap(enum nssdb_type nssdb_type, id_t *id, const char *name, bool *hide)
{
	/* Set 'id' to the new UID/GID 'id' has to be replaced to.
	   Set 'hide' according to whether the entry should be hidden or not. */
	struct idmapping *p_map;
	struct stat st;
	char **p_name;
	
	read_idmap();
	if(hide != NULL) *hide = FALSE;
	p_name = (char **)&name;
	
	for(p_map = idmappings; p_map != NULL; p_map = p_map->next)
	{
		bool rule_matched;
		
		rule_matched = FALSE;
		
		if(p_map->nssdb_type == nssdb_type)
		{
			if(p_map->name_from != NULL)
			{
				if(*p_name == NULL)
				{
					/* we're gona map by user/group name, but the name was not known
					   by the caller, so resolve it now */
					*p_name = lazy_resolve_name(nssdb_type, *id);
				}
				if(*p_name == NULL)
				{
					/* user/group name can not be resolved.
					   let's skip this rule. */
					continue;
				}
				if(strcmp(p_map->name_from, *p_name)==0)
				{
					rule_matched = TRUE;
				}
			}
			else if((p_map->id_from_start <= *id && p_map->id_from_end >= *id) ||
			   (p_map->id_from_start == *id && p_map->id_from_end == 0))
			{
				rule_matched = TRUE;
			}
			
			if(rule_matched)
			{
				char *path;
				
				DEBUGPRINT("(libnss_idmap: forward map %cid %d ", NSSDB_TYPE_CHAR, *id);
				
				if(p_map->statpath != NULL)
				{
					char *id_str;
					
					path = abstrdup(p_map->statpath);
					id_str = abmalloc(n_digits(*id) + 1);
					sprintf(id_str, "%u", *id);
					abstrrepl(&path, "{ID}", id_str);
					free(id_str);
					
					if(strstr(path, "{NAME}") != NULL && *p_name == NULL)
					{
						/* 'name' was not known by caller, let's find it now */
						*p_name = lazy_resolve_name(nssdb_type, *id);
						if(*p_name == NULL)
						{
							/* The passwd/group entry for the given Id was not found, 
							   but it is needed to construct the file name. So treat 
							   it like stat(2) errors. */
							goto stat_path_error;
						}
					}
					abstrrepl(&path, "{NAME}", *p_name);
					
					if(stat(path, &st) == 0)
					{
						*id = nssdb_type == NSSDB_PASSWD ? st.st_uid : st.st_gid;
						
						DEBUGPRINT("to %d as %s)\n", *id, path);
					}
					else
					{
						stat_path_error:
						if(p_map->on_stat_error == STATERR_HIDE)
						{
							if(hide != NULL) *hide = TRUE;
							
							DEBUGPRINT("to - as %s failed)\n", path);
						}
						else if(p_map->on_stat_error == STATERR_IGNORE)
						{
							DEBUGPRINT("... [%s failed])\n", path);
							
							free(path);
							continue;
						}
					}
					free(path);
				}
				else if(p_map->hide)
				{
					if(hide != NULL) *hide = TRUE;
					
					DEBUGPRINT("to -)\n");
				}
				else
				{
					if(p_map->intv == MAPINTV_N_TO_1)
						*id = p_map->id_to;
					else
						*id = p_map->id_to + (*id - p_map->id_from_start);
					
					DEBUGPRINT("to %d)\n", *id);
				}
				break;
			}
		}
	}
	
	if(*p_name != name) free(*p_name);
}

id_t get_id_to_be_replaced(const struct idmapping *p_map, const id_t new_id, const id_t * backend_id, bool * found)
{
	/* Returns the ID which has to be replaced to 'new_id'
	   according to rule pointed by 'p_map'.
	   Indicate if it was found in '*found' parameter, check it before
	   consume return value.
	   Caller may supply pointer to uid/gid of the named entity in 'backend_id' 
	   if it's a name-based rule and the ID is known by the caller (to reduce
	   unnecessary nss lookup here) or leave it NULL.
	   It respects to 'name_from' field.
	   Used in reverse mapping. */
	
	*found = FALSE;
	
	if(p_map->name_from != NULL)
	{
		/* it's a name-based rule */
		if(backend_id != NULL)
		{
			*found = TRUE;
			return *backend_id;
		}
		else
			return lazy_resolve_id(p_map->nssdb_type, p_map->name_from, found);
	}
	else
	{
		/* it's an ID-based rule */
		*found = TRUE;
		if(p_map->intv == MAPINTV_N_TO_1)
			/* NOTE: ambiguous reverse mapping */
			return p_map->id_from_start;
		else
			return p_map->id_from_start + (new_id - p_map->id_to);
	}
	/* return value is undefined (*found==FALSE) here */
	return -1;
}

bool verify_mapping(struct idmapping * p_map, id_t id_to, id_t * id_from)
{
	/* Verify whether base ID of this rule (uid/gid defined in the rule
	   to be replaced, or uid/gid of the named entity defined in the
	   name-based rule) really maps to 'id_to'.
	   If so, save the base ID to 'id_from' as a side effect. */
	id_t forward_map_id;
	id_t verify_id;
	bool hide;
	bool id_found;
	
	forward_map_id = get_id_to_be_replaced(p_map, id_to, NULL, &id_found);
	if(!id_found)
	{
		/* we don't know what is the ID of this named entity, so it probably 
		   does not even exist. let's invalidate this verification. */
		return FALSE;
	}
	verify_id = forward_map_id;
	do_idmap(p_map->nssdb_type, &verify_id, NULL, &hide);
	
	if(verify_id == id_to && !hide)
	{
		*id_from = forward_map_id;
		return TRUE;
	}
	else
	{
		/* the complete ruleset maps 'forward_map_id' to something
		   else than 'id_to' */
		return FALSE;
	}
}

void do_idmap_reverse(enum nssdb_type nssdb_type, id_t *id)
{
	struct idmapping *p_map;
	
	read_idmap();
	
	DEBUGPRINT("(libnss_idmap: reverse map %cid %d back ", NSSDB_TYPE_CHAR, *id);
	
	for(p_map = idmappings; p_map != NULL; p_map = p_map->next)
	{
		if(p_map->nssdb_type != nssdb_type) continue;
		
		id_t forward_map_id;
		
		if(p_map->statpath != NULL)
		{
			/* This rule maps to file uid/gid. */
			/* Scan all possible files to find out which one has '*id'. */
			/* NOTE: this is IO expensive */
			
			char *path;
			glob_t matches;
			int idx;
			bool id_found;
			
			id_found = FALSE;
			path = abstrdup(p_map->statpath);
			abstrrepl(&path, "{ID}", "?*");
			abstrrepl(&path, "{NAME}", "?*");
			glob(path, GLOB_NOSORT, NULL, &matches);
			
			for(idx = 0; matches.gl_pathv != NULL && matches.gl_pathv[idx] != NULL; idx++)
			{
				/* Check that uid/gid of this file equals to '*id' */
				struct stat st;
				
				DEBUGPRINT("[%s] ", matches.gl_pathv[idx]);
				
				if(stat(matches.gl_pathv[idx], &st) == 0)
				{
					id_t file_id;
					
					file_id = (id_t)(nssdb_type == NSSDB_PASSWD ? st.st_uid : st.st_gid);
					if(file_id == *id)
					{
						/* This file has uid/gid which we want to find out which uid/gid
						   maps to. Verify that uid/gid/username/groupname of this rule really 
						   maps to this file's uid/gid, because it may have been covered 
						   earlier or path pattern may not match at all. */
						
						if(verify_mapping(p_map, *id, &forward_map_id))
						{
							/* UID/GID of this rule was the one which maps to the '*id' in the reverse mapping call. */
							*id = forward_map_id;
							id_found = TRUE;
						}
						
						break;
					}
				}
				else
				{
					/* stat(2) error happened, but it has not neccessarily been on a file defined
					   in the config file, so ignore what p_map->on_stat_error commands. */
				}
			}
			
			globfree(&matches);
			if(id_found)
			{
				DEBUGPRINT("to %d", *id);
				break;
			}
			else
			{
				DEBUGPRINT("... [rule '%s' mismatched] ", p_map->statpath);
			}
		}
		
		else if((p_map->intv == MAPINTV_N_TO_1 && p_map->id_to == *id) ||
		   (p_map->intv == MAPINTV_N_TO_N && p_map->id_to <= *id && (p_map->id_to + (p_map->id_from_end - p_map->id_from_start)) >= *id))
		{
			/* This rule maps to 1 or more ID. */
			
			if(verify_mapping(p_map, *id, &forward_map_id))
			{
				/* UID/GID of this rule was the one which maps to the '*id' in the reverse mapping call. */
				*id = forward_map_id;
				DEBUGPRINT("to %d", *id);
				break;
			}
			DEBUGPRINT("... [rule mismatched] ");
		}
	}
	DEBUGPRINT(")\n");
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
		
		/* Note: if there was no id mapping here, then you may get an entry with
		   the same id as some other entry with mapped id. To prevent it, add
		   an explicite hide rule, like:
		     uid 1000 to 1001
		     uid 1001 hide
		   or:
		     user alice to 1001
		     user bob hide
		   Not hiding the replacement ID would lead to alice and bob both had
		   UID 1001, given that alice:1000 and bob:1001 in the upstream nss modules. */
		
		// TODO: address above issue in case of file-based mapping
		
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
		   and lookup that UID in the upstream modules */
		lookup_uid = uid;
		do_idmap_reverse(NSSDB_PASSWD, (id_t*)&lookup_uid);
		
		if(lookup_uid == uid)
		{
			/* There is no source UID mapped to the requested UID.
			   check if the requested UID maps to something else,
			   if so then return "not found". */
			
			/* TODO: to reduce internal nss lookups, 'name' parameter 
			   may be passed to do_idmap() if do_idmap_reverse() above 
			   obtained the it during its runtime. 
			   but we must either copy the string or disable the next
			   read_idmap() call to prevent it to free() the pointer 
			   which points to the name in a mapping rule. */
			
			do_idmap(NSSDB_PASSWD, (id_t*)&lookup_uid, NULL, &hide);
			if(lookup_uid != uid || hide)
			{
				/* don't show this entry, because it has an UID 
				   which has to be replaced or hidden */
				return NSS_STATUS_NOTFOUND;
			}
		}
		
		/* TODO: we can reduce internal nss lookups by having _nss_idmap_getXXuid_r
		   to lookup entry not by uid but by name when there is a name-based rule
		   in idmappings to the requested ID. */
		
		passthrough_mode = TRUE;
		error = getpwuid_r(lookup_uid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
		HANDLE_ERRORS_R;
		
		/* Note: you won't necessarily get back the requested UID
		   if you defined N:1 (overloaded) mapping to the requested UID. */
		
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
		
		// TODO: see issue in _nss_idmap_getpwnam_r()
		
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
		
		/* Perform reverse mapping.
		   See comments in _nss_idmap_getpwuid_r() why is it needed. */
		
		lookup_gid = gid;
		do_idmap_reverse(NSSDB_GROUP, (id_t*)&lookup_gid);
		
		if(lookup_gid == gid)
		{
			do_idmap(NSSDB_GROUP, (id_t*)&lookup_gid, NULL, &hide);
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
