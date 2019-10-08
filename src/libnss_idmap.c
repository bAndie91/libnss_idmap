
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

static int passthrough_mode;


enum nss_status
_nss_idmap_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
	fprintf(stderr, "ok\n");
	if(passthrough_mode)
	{
		return NSS_STATUS_UNAVAIL;
	}
	else
	{
		passthrough_mode = TRUE;
		enum nss_status r = getpwnam_r(name, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
//		DO_IDMAP
		return r;
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
		passthrough_mode = TRUE;
		enum nss_status r = getpwuid_r(uid, result, buffer, buflen, &result);
		passthrough_mode = FALSE;
//		DO_IDMAP
		return r;
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
