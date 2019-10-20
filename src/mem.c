/* Memory-, string-handling and other low-level functions */

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
