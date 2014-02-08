#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <mysql/mysql.h>
#include <cgi.h>
#include <fcgi_stdio.h>
#include "utils.h"
#include "webapp.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define ESCAPE(x) char escaped_ ## x[512]; mysql_real_escape_string(con, escaped_ ## x, x, strlen(x));

char *sha512(char *string)
{
    unsigned char digest[SHA512_DIGEST_LENGTH], digest_new[SHA512_DIGEST_LENGTH];
    
    SHA512(string, strlen(string), digest);    

    int i;
    for (i=0; i<101010; i++)
    {
    	SHA512(digest, sizeof(digest), digest_new);    
	memcpy(digest, digest_new, SHA512_DIGEST_LENGTH);
    }

    char mdString[SHA512_DIGEST_LENGTH*2+1];

    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    return strdup(mdString);
}

char *hmac_hash(char *data)
{
    char *key = "my_secret_key";

    unsigned char* digest;
    
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    digest = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);    

    char mdString[45];
    int i;
    for(i = 0; i < 20; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    return strdup(mdString);
}

char* read_file(char* filename)
{
    FILE* file = fopen(filename,"r");
    if(file == NULL)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    rewind(file);

    char* content = calloc(size + 1, 1);

    fread(content,1,size,file);

    return content;
}

// int is_authenticated(){
// 	s_cgi *cgi;
// 	s_cookie *cookie;
// 	cgi = cgiInit();
// 	cookie = cgiGetCookie(cgi, "Authenticated");
// 	if(cookie != NULL){
// 		if(strcmp(cookie->value,"yes") == 0){
// 			return 1;
// 		}
// 	}
// 	return 0;
// }

char *get_session_username(){
	s_cgi *cgi;
	s_cookie *cookie;
	cgi = cgiInit();
	cookie = cgiGetCookie(cgi, "Username");

	if (cookie == NULL) {
		return NULL;
	}

	int count = 0;

	char *c;
	for (c = cookie->value; *c; c++) {
		if (*c == '|')
			count++;
	}

	if (count != 1)
		return NULL;

	char *name, *sig;

	name = strtok(cookie->value, "|");
	sig = strtok(NULL, "|");

	if (name == NULL || sig == NULL)
		return NULL;

	char *expected = hmac_hash(name);
	if (strcmp(sig, expected) != 0)
	{
		free(expected);
		return NULL;
	}

	return strdup(name);
}

int authenticate(char *username, char *password) {
	MYSQL *con = mysql_init(NULL);

	if (con == NULL || strlen(username) > 255){
		return 0;
	}

        // use the real functions
        // https://www.youtube.com/watch?v=_jKylhJtPmI
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL){
		mysql_close(con);
		return 0;
	}

	ESCAPE(username)

	// prepared statement to select username
	char query[1024];
	sprintf(query, "SELECT Password FROM Users WHERE Username='%s';", escaped_username);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	int result = 0;
	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		char *hashed_password = sha512(password);

		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){
				if(strcmp(hashed_password,row[0]) == 0){
					result = 1; // correct password
				} // else incorrect password
			} // shouldn't happen I don't think
		} // else user does not exist
		mysql_free_result(users);
		free(hashed_password);
	}

	mysql_close(con);

	if (!result)
	{
   	    openlog ("webapp", 0, 0);
            syslog (LOG_AUTH, "Authencation failed for user %s, from ip %s", username, getenv("REMOTE_ADDR"));
            closelog ();
	}

	return result;
}

char *get_field_for_username(char *username, char *field){
	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

	ESCAPE(username)

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL){
		mysql_close(con);
		return 0;
	}

	char query[1024];
	snprintf(query, 1024, "SELECT %s FROM Users WHERE Username='%s';", field, escaped_username);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){
				mysql_close(con);
				return strdup(row[0]);
			} // shouldn't happen...I don't think
		} // else user does not exist
		mysql_free_result(users);
	}

	mysql_close(con);
	return NULL;
}

char *escape_html(char *html)
{
	int len = strlen(html);
	char *cursor;
	for (cursor=html; *cursor; cursor++)
	{
		switch (*cursor)
		{
			case '&':
				len += 4;
				break;
			case '<':
			case '>':
				len += 3;
				break;
			case '"':
			case '\'':
				len += 5;
				break;
		}
	}
	char *result = malloc(len + 5);
	memset(result, 0, len + 5);
	char *result_cursor = result;

	for (cursor=html; *cursor; cursor++)
	{
	
		switch (*cursor)
		{
			case '&':
				strcpy(result_cursor, "&amp;");
				result_cursor += 4;
				break;
			case '<':
				strcpy(result_cursor, "&lt;");
				result_cursor += 3;
				break;
			case '>':
				strcpy(result_cursor, "&gt;");
				result_cursor += 3;
				break;
			case '"':
				strcpy(result_cursor, "&#034;");
				result_cursor += 5;
				break;
			case '\'':
				strcpy(result_cursor, "&#039;");
				result_cursor += 5;
				break;
			default:
				*result_cursor = *cursor;
				result_cursor++;
		}
	}

	return result;
}

char *get_first_name(char *username){
	return escape_html(get_field_for_username(username, "FirstName"));
}

char *get_last_name(char *username){
	return escape_html(get_field_for_username(username, "LastName"));
}

int is_admin(char *username){
	return strcmp("Y", get_field_for_username(username, "IsAdmin")) == 0;
}

// TODO: We should probably hash these passwords or something...
// Source: https://www.youtube.com/watch?v=8ZtInClXe1Q
int add_user(char *username, char *password, char *first_name, char *last_name, char *ssn, char is_admin) {
	MYSQL *con = mysql_init(NULL);

	if (con == NULL || is_admin == '\''){
		return 0;
	}

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL){
		mysql_close(con);
		return 0;
	}
	ESCAPE(username)
	ESCAPE(first_name)
	ESCAPE(last_name)
	ESCAPE(ssn)
	char *hashed_password = sha512(password);

	// using a prepared statement for security
	char query[1024];
	snprintf(query, 1024, "INSERT INTO Users (Username, Password, FirstName, LastName, SSN, IsAdmin) VALUES ('%s','%s','%s','%s', '%s', '%c');", escaped_username, hashed_password, escaped_first_name, escaped_last_name, escaped_ssn, is_admin);

	free(hashed_password);
	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

// day should be in format yyyy-mm-dd
int add_entry(char *username, char *day, char *minutes_worked){
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL) {
		mysql_close(con);
		return;
	}

	ESCAPE(username)
	ESCAPE(day)
	ESCAPE(minutes_worked)
	char query[1024];
	snprintf(query, 1024, "INSERT INTO Entries (Username, Day, MinutesWorked, ApprovedBy) VALUES ('%s', '%s', '%s', 'Not Approved');", escaped_username, escaped_day, escaped_minutes_worked);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

int approve_entry(char *username, char *day){
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL) {
		mysql_close(con);
		return;
	}

	ESCAPE(username);
	ESCAPE(day);
	char query[1024];
	snprintf(query, 1024, "UPDATE Entries SET ApprovedBy='Approved' WHERE Username='%s' AND Day='%s';", escaped_username, escaped_day);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return;
	}

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

void render_entries_json(response *res, char *username, char *start_date, char *end_date) {
	response_write(res, "{ \"entries\": [");
	char *prepend = "";	
	if(username != NULL && start_date != NULL && end_date != NULL){
		MYSQL *con;
		if (!(con = mysql_init(NULL))) {
			return;
		}

		if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL) {
			mysql_close(con);
			return;
		}

		char query[512]; 
		sprintf(query, "SELECT * FROM Entries WHERE Username = '%s' AND Day BETWEEN '%s' AND '%s';", username, start_date, end_date);

		if (mysql_query(con, query)) {
			mysql_close(con);
			return;
		}

		MYSQL_RES *result = mysql_store_result(con);
		unsigned int num_fields = mysql_num_fields(result);
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result))) {
			unsigned long *lengths = mysql_fetch_lengths(result);
			unsigned int i;
			if(num_fields == 4){
				response_write(res, prepend);
				prepend = ",";
				char result[1024];
				char *day_value = row[1] ? row[1] : "NULL";
				char *minutes_worked_value = row[2] ? row[2] : "NULL";
				char *approved_by_value = row[3] ? row[3] : "NULL";
				sprintf(result, "{ \"day\":\"%s\", \"minutes\":\"%s\",\"approver\":\"%s\" }", day_value, minutes_worked_value, approved_by_value);
				response_write(res, result);
			}
		}

		mysql_close(con);
		
	}
	response_write(res, "]}");
}

void dump_tables(response *res) {
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, 0) == NULL) {
		mysql_close(con);
		return;
	}

	char query[] = "SELECT Username, FirstName, LastName, SSN, IsAdmin FROM Users ORDER BY LastName, FirstName";

	if (mysql_query(con, query)) {
		mysql_close(con);
		return;
	}

	MYSQL_RES *result = mysql_store_result(con);
	unsigned int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		unsigned long *lengths = mysql_fetch_lengths(result);
		unsigned int i;
		if(res != NULL) response_write(res, "<tr>");
		for (i = 0; i < num_fields; ++i ) {
			printf("%.*s,", lengths[i], row[i] ?: "NULL");
			char field[512];
			char *value = row[i] ? row[i] : "NULL";
			if(i==0){
				sprintf(field, "<td><a href=\"/webapp/timesheet?user=%s\">%s</a></td>", escape_html(value), escape_html(value));
			} else {
				sprintf(field, "<td>%s</td>", escape_html(value));
			}
			
			if(res != NULL) response_write(res, field);
		}
		if(res != NULL) response_write(res, "</tr>");
	}

	mysql_close(con);
}

