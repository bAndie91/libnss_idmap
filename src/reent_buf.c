/* Functions to manage the buffer of reentrant nss functions. */

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
	/* Copy src into buffer, point dst to the copy,
	   move the buffer's pointer to the remaining free space.
	   Caller must satisfy the buffer size in prior. */
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
