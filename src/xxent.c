/* Functions to manage passwd/group structures. */

void copy_pwent(struct passwd *dst, struct passwd *src)
{
	/* copy over a passwd entry to an other */
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
	/* copy over a group entry to an other */
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

void free_pwentry_fields(struct passwd *pwd)
{
	free(pwd->pw_name);
	free(pwd->pw_passwd);
	free(pwd->pw_gecos);
	free(pwd->pw_dir);
	free(pwd->pw_shell);
}

void free_grentry_fields(struct group *grp)
{
	unsigned int idx_mem;
	for(idx_mem = 0; grp->gr_mem != NULL && grp->gr_mem[idx_mem] != NULL; idx_mem++)
		free(grp->gr_mem[idx_mem]);
	free(grp->gr_mem);
	free(grp->gr_passwd);
	free(grp->gr_name);
}
