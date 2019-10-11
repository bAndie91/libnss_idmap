enum nss_status
IDMAP_SETENT(int stayopen)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		STRUCTNAME *entry;
		unsigned int idx_entry;
		
		passthrough_mode = TRUE;
		FREE_ENTRIES();
		
		/* load shared library in a separate address space,
		   because in the main address space setXXent and getXXent are locked at this point */
		void *libc = dlmopen(LM_ID_NEWLM, LIBC_NAME, RTLD_LAZY | RTLD_DEEPBIND);
		char *e = dlerror();
		if(e)
		{
			warnx("libnss_idmap: %s", e);
			passthrough_mode = FALSE;
			return NSS_STATUS_UNAVAIL;
		}
		void (* _setXXent)(void) = dlsym(libc, SETENTNAME);
		void (* _endXXent)(void) = dlsym(libc, ENDENTNAME);
		STRUCTNAME * (* _getXXent)(void) = dlsym(libc, GETENTNAME);
		
		/* load passwd/group entries from upstream module into memory */
		_setXXent();
		idx_entry = 0;
		while((entry = _getXXent()) != NULL)
		{
			GETENT_ARRAY = realloc(GETENT_ARRAY, (idx_entry+2) * sizeof(STRUCTNAME));
			if(GETENT_ARRAY == NULL) abort();
			
			COPY_STRUCT(&(GETENT_ARRAY[idx_entry]), entry);
			
			idx_entry++;
			GETENT_ARRAY[idx_entry].GETENT_NAME = NULL;
		}
		
		/* point pw entry pointer to the beginning of the array */
		GETENT_POINTER = GETENT_ARRAY;
		/* close secondary address space */
		_endXXent();
		dlclose(libc);
		
		passthrough_mode = FALSE;
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
IDMAP_ENDENT()
{
	if(passthrough_mode)
		return NSS_STATUS_UNAVAIL;
	else
	{
		FREE_ENTRIES();
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status
IDMAP_GETENT(STRUCTNAME *result, char *buffer, size_t buflen, int *errnop)
{
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		bool hide;
		
		while(TRUE)
		{
			if(GETENT_POINTER == NULL || GETENT_POINTER->GETENT_NAME == NULL)
			{
				/* we're out of pw/gr entries */
				/* ensure there is "[NOTFOUND=return]" in nsswitch.conf to avoid duplicate entries */
				return NSS_STATUS_NOTFOUND;
			}
			
			if(buflen < SIZEOF_ENTRY(GETENT_POINTER))
			{
				/* given buffer is too small */
				*errnop = ERANGE;
				return NSS_STATUS_TRYAGAIN;
			}
			
			COPY_TO_RESULT(buffer, result, GETENT_POINTER);
			
			DO_IDMAP(result, &hide);
			
			/* move pointer forward */
			GETENT_POINTER = &GETENT_POINTER[1];
			
			if(hide) continue;
			
			return NSS_STATUS_SUCCESS;
		}
	}
}
