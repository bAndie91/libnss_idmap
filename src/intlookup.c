/* Functions for internal NSS lookup. */

void * in_new_address_space(void ** addrspace_hndl, const char * func_name)
{
	/* Erect a new address space.
	   Return the given function from that address space.
	   Abort on memory error.
	   Caller must dlclose(). */
	char *dlerr;
	
	*addrspace_hndl = dlmopen(LM_ID_NEWLM, LIBC_NAME, RTLD_LAZY | RTLD_DEEPBIND);
	dlerr = dlerror();
	if(dlerr)
	{
		warnx("libnss_idmap: %s", dlerr);
		abort();
	}
	return dlsym(*addrspace_hndl, func_name);
}

struct passwd * nolock_getpwuid(uid_t uid)
{
	/* Calls getpwuid() in a new address space to circumvent libc lock.
	   Caller must free memory pointed by resulting pointer recursively.
	   See free_pwentry_fields() */
	void *libc;
	struct passwd *tmp_pwd;
	struct passwd *result_pwd;
	bool pt_mode;
	
	struct passwd * (* _getpwuid)(uid_t) = in_new_address_space(&libc, "getpwuid");
	
	pt_mode = passthrough_mode;
	passthrough_mode = TRUE;
	tmp_pwd = _getpwuid(uid);
	passthrough_mode = pt_mode;
	if(tmp_pwd == NULL)
		result_pwd = NULL;
	else
	{
		/* Copy out passwd entry from temporary static address space 
		   to our main address space. */
		result_pwd = abmalloc(sizeof(struct passwd));
		copy_pwent(result_pwd, tmp_pwd);
	}
	
	dlclose(libc);
	return result_pwd;
}

struct group * nolock_getgrgid(gid_t gid)
{
	/* Similar to nolock_getpwuid(). See there. */
	void *libc;
	struct group *tmp_grp;
	struct group *result_grp;
	bool pt_mode;
	
	struct group * (* _getgrgid)(gid_t) = in_new_address_space(&libc, "getgrgid");
	
	pt_mode = passthrough_mode;
	passthrough_mode = TRUE;
	tmp_grp = _getgrgid(gid);
	passthrough_mode = pt_mode;
	if(tmp_grp == NULL)
		result_grp = NULL;
	else
	{
		result_grp = abmalloc(sizeof(struct group));
		copy_grent(result_grp, tmp_grp);
	}
	
	dlclose(libc);
	return result_grp;
}

struct passwd * nolock_getpwnam(const char * name)
{
	/* Similar to nolock_getpwnam(). See there. */
	void *libc;
	struct passwd *tmp_pwd;
	struct passwd *result_pwd;
	bool pt_mode;
	
	struct passwd * (* _getpwnam)(char*) = in_new_address_space(&libc, "getpwnam");
	
	pt_mode = passthrough_mode;
	passthrough_mode = TRUE;
	tmp_pwd = _getpwnam((char*)name);
	passthrough_mode = pt_mode;
	if(tmp_pwd == NULL)
		result_pwd = NULL;
	else
	{
		result_pwd = abmalloc(sizeof(struct passwd));
		copy_pwent(result_pwd, tmp_pwd);
	}
	
	dlclose(libc);
	return result_pwd;
}

struct group * nolock_getgrnam(const char * name)
{
	/* Similar to nolock_getgrgid(). See there. */
	void *libc;
	struct group *tmp_grp;
	struct group *result_grp;
	bool pt_mode;
	
	struct group * (* _getgrnam)(char*) = in_new_address_space(&libc, "getgrnam");
	
	pt_mode = passthrough_mode;
	passthrough_mode = TRUE;
	tmp_grp = _getgrnam((char*)name);
	passthrough_mode = pt_mode;
	if(tmp_grp == NULL)
		result_grp = NULL;
	else
	{
		result_grp = abmalloc(sizeof(struct group));
		copy_grent(result_grp, tmp_grp);
	}
	
	dlclose(libc);
	return result_grp;
}

char * lazy_resolve_name(const enum nssdb_type nssdb_type, const id_t id_from)
{
	/* You can free() resulting pointer. */
	struct passwd *pwd;
	struct group *grp;
	char * name;
	
	name = NULL;
	
	if(nssdb_type == NSSDB_PASSWD)
	{
		pwd = nolock_getpwuid(id_from);
		if(pwd != NULL)
		{
			name = abstrdup(pwd->pw_name);
			free_pwentry_fields(pwd);
			free(pwd);
		}
	}
	else
	{
		grp = nolock_getgrgid(id_from);
		if(grp != NULL)
		{
			name = abstrdup(grp->gr_name);
			free_grentry_fields(grp);
			free(grp);
		}
	}
	return name;
}						

id_t lazy_resolve_id(const enum nssdb_type nssdb_type, const char * name_from, bool * found)
{
	/* Resolve a user/group name to UID/GID by upstream NSS modules
	   and return the ID if it was found.
	   Indicate if it was found in '*found' parameter, check it before
	   consuming return value. */
	struct passwd *pwd;
	struct group *grp;
	id_t id;
	
	*found = FALSE;
	
	if(nssdb_type == NSSDB_PASSWD)
	{
		pwd = nolock_getpwnam(name_from);
		if(pwd != NULL)
		{
			*found = TRUE;
			id = (id_t)pwd->pw_uid;
			free_pwentry_fields(pwd);
			free(pwd);
		}
	}
	else
	{
		grp = nolock_getgrnam(name_from);
		if(grp != NULL)
		{
			*found = TRUE;
			id = (id_t)grp->gr_gid;
			free_grentry_fields(grp);
			free(grp);
		}
	}
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
	return id;
	#pragma GCC diagnostic pop
}
