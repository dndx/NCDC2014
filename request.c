/*
    Copyright (C) 2011 Raphters authors,
    
    This file is part of Raphters.
    
    Raphters is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Raphters is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <uriparser/Uri.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include "request.h"
#include "fcgi_stdio.h"


char *get_referer() {
    return getenv("HTTP_REFERER");
}

char *get_user_agent() {
    return getenv("HTTP_USER_AGENT");
}

char *get_path_info() {
    return getenv("PATH_INFO");
}

char *get_query_string() {
    return getenv("QUERY_STRING");
}

// note this method only returns data once for each request
// stdin cannot be rewinded
char *get_post_string() {
	char *contentLength = get_content_length();
	int len;

	if (contentLength != NULL) {
		len = strtol(contentLength, NULL, 10);
	} else {
		len = 0;
	}

	char *data = malloc((len+1) * sizeof(char));
	FCGI_fgets(data, len+1, FCGI_stdin);
	return data;
}

char *get_content_length() {
	return getenv("CONTENT_LENGTH");
}

char *get_remote_addr() {
    return getenv("REMOTE_ADDR");
}

char *get_method() {
    return getenv("REQUEST_METHOD");
}

char *get_server_name() {
    return getenv("SERVER_NAME");
}

char *get_server_port() {
    return getenv("SERVER_PORT");
}

char *get_param(char *query_string, char *name) {
	char *url = "https://www.team9.isucdc.com?"; // just a place holder to maker the parser happy
	char *uri_string = malloc((strlen(url) + strlen(query_string)));
	strcpy(uri_string,url);
	strcat(uri_string,query_string);

	// parse up the uri string
	UriParserStateA state;
	UriUriA uri;
	state.uri = &uri;
	if (uriParseUriA(&state, uri_string) == URI_SUCCESS) {
		UriQueryListA *queryList;
		int itemCount;
		if (uriDissectQueryMallocA(&queryList, &itemCount, uri.query.first, uri.query.afterLast) == URI_SUCCESS) {
			UriQueryListA *itemPtr = queryList;
			int i;
			for (i = 0; i < itemCount && itemPtr != NULL; i++, itemPtr = itemPtr->next) {
				if(strcmp(name,itemPtr->key) == 0){
					char *result = malloc((strlen(itemPtr->value)));
					strcpy(result, itemPtr->value);
					uriFreeQueryListA(queryList);
					uriFreeUriMembersA(&uri);
					return result;
				}
			}
		}
		uriFreeQueryListA(queryList);
	}
	uriFreeUriMembersA(&uri);

	return NULL;
}

long long current_timestamp() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // milliseconds
    return milliseconds;
}

// not all data is ascii encode, this method should be
// used when multipart encoded form data
void *get_post_data(){
	char *data = get_param(get_post_string(), "data");
	void *result;
	if(data != NULL){
		int i = 0; int j = 0; int k = 0; char buf[3];
		unsigned char tmp[1024]; // just read data stream 1kb at a time
		for (i = 0; i < strlen(data) && i < 1024; i++){
			if(isxdigit(data[i])){
				buf[j++] = data[i];
				if(j == 2){
					buf[2] = '\0';
					tmp[k++]=strtol(buf, NULL, 16);
					j = 0;
				}
			}
		}
		unsigned char *dat = malloc(k * sizeof(unsigned char));
		memcpy(dat, tmp, k);
		result = mmap (0,k,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANON,-1,0);
		memcpy(result, dat, k);
		// multipart form data, write it to temporary storage so we can access it later
		char tmpf[100];
		sprintf(tmpf, "/tmp/tmp_%lld", current_timestamp());
		FILE *binFile = fopen(tmpf,"w+");
		fwrite(data, sizeof(unsigned char), k, binFile);
		fclose(binFile);
		return result;
	}
	return NULL; // invalid form data
}
