#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/stat.h>

#include <curl/curl.h>

#define max_args 2
#define html_file_pos 1

#define api_url "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev"
#define api_key "x-api-key: comp112z5q0sstvs1ejt9y2rqxixxywqlm7eckwucsriwao"
#define model_id "4o-mini"

file *open_or_abort(char *filename)
{
  if (!filename)
  {
    return null;
  }

  file *ptr = fopen(filename, "r");
  if (ptr == null)
  {
    fprintf(stderr, "could not open filename: %s\n", filename);
    exit(exit_failure);
  }
  return ptr;
}

long get_file_size(char *file_name)
{
  if (file_name == null)
  {
    return -1;
  }

  struct stat stats;
  if (stat(file_name, &stats) == 0)
  {
    return stats.st_size;
  }

  return -1;
}

char *get_contents(char *filename)
{
  int file_size = get_file_size(filename);

  file *file = fopen(filename, "r");
  if (file == null)
  {
    return null;
  }

  char *html = calloc(file_size + 1, sizeof(char));

  int pos = 0;
  int ch;
  while ((ch = fgetc(file)) != eof)
  {
    html[pos] = ch;
    pos++;
  }

  html[pos] = '\0';

  fclose(file);
  return html;
}

bool is_opening_paragraph_tag(char *html, unsigned int pos)
{
  return html[pos] == '<' && html[pos + 1] == 'p' && html[pos + 2] == '>';
}

bool is_closing_paragraph_tag(char *html, unsigned int pos)
{
  return html[pos] == '<' && html[pos + 1] == '/' && html[pos + 2] == 'p' && html[pos + 3] == '>';
}

bool is_edit_word(char *html, unsigned int pos)
{
  return html[pos] == 'e' && html[pos + 1] == 'd' && html[pos + 2] == 'i' && html[pos + 3] == 't';
}

bool is_references_section(char *html, unsigned int pos)
{
  char *target = "references";
  for (int i = 0; target[i] != '\0'; i++)
  {
    if (target[i] != html[pos])
    {
      return false;
    }
    pos++;
  }

  return true;
}

char *parse_body(char *html_content)
{
  // todo: figure out if this is the best approach?
  char *body_start = strstr(html_content, "<div id=\"bodycontent\"");
  int str_len = strlen(html_content);

  char *content_buffer = calloc(str_len, sizeof(char));
  int pos = 0;

  bool is_content = false;

  // this loop only copies the contents inbetween <p> and </p> tags
  // not very optimal but the best approach for now
  for (int i = 0; body_start[i] != '\0'; i++)
  {
    // find the opening p tag, copy content until we find the closing tag
    {

      if (is_references_section(body_start, i))
      {
        break;
      }

      if (is_opening_paragraph_tag(body_start, i))
      {
        // skip the <p> tag
        i += 3;
        is_content = true;
      }

      if (is_content)
      {
        // remove all html tags and html tag contents
        if (body_start[i] == '<')
        {
          while (body_start[i] != '>')
          {
            i++;
          }
        }

        // remove html entities 
        if (body_start[i] == '&')
        {
          while (body_start[i] != ';')
          {
            i++;
          }
        }

        // ignore all occurances of the following list of characters 
        if (body_start[i] == '"' || body_start[i] == '\"' || body_start[i] == '>' || body_start[i] == '[' || body_start[i] == ']')
        {
          continue;
        }

        if (body_start[i] == '\n')
        {
          content_buffer[pos] = ' ';
        } 
        else 
        {
          content_buffer[pos] = body_start[i];
        }
        pos++;

      }

      if (is_closing_paragraph_tag(body_start, i))
      {
        // skip the </p> tag
        i += 4;
        is_content = false;
      }
    }
  }

  content_buffer[pos] = '\0';

  return content_buffer;
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data)
{
  size_t total_size = size * nmemb; // total size of received data
  strncat(data, ptr, total_size);   // append the received data to the buffer
  return total_size;
}

void llmproxy_request(char *model, char *system, char *query, char *response_body)
{
  curl *curl;
  curlcode res;

  char *request_fmt = "{\n"
                      "  \"model\": \"%s\",\n"
                      "  \"system\": \"%s\",\n"
                      "  \"query\": \"%s\",\n"
                      "  \"temperature\": %.2f,\n"
                      "  \"lastk\": %d,\n"
                      "  \"session_id\": \"%s\"\n"
                      "}";

  // json data to send in the post request
  char request[100000] = {0};
  memset(request, 0, 100000);
  snprintf(request,
           sizeof(request),
           request_fmt,
           model,
           system,
           query,
           0.0,
           1,
           "genericsession");

  printf("initiating request: %s\n", request);

  // initialize curl
  curl = curl_easy_init();
  if (curl)
  {
    // set the url of the proxy agent server server
    curl_easy_setopt(curl, curlopt_url, api_url);

    // set the content-type to application/json
    struct curl_slist *headers = null;
    headers = curl_slist_append(headers, "content-type: application/json");

    // add x-api-key to header
    headers = curl_slist_append(headers, api_key);
    curl_easy_setopt(curl, curlopt_httpheader, headers);

    curl_easy_setopt(curl, curlopt_httpheader, headers);

    // add request
    curl_easy_setopt(curl, curlopt_postfields, request);

    // set the write callback function to capture response data
    curl_easy_setopt(curl, curlopt_writefunction, write_callback);

    // set the buffer to write the response into
    curl_easy_setopt(curl, curlopt_writedata, response_body);

    // perform the post request
    res = curl_easy_perform(curl);

    // check if the request was successful
    if (res != curle_ok)
    {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    // cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  else
  {
    fprintf(stderr, "failed to initialize curl.\n");
  }
}

// is there a query limit?
int main(int argc, char **argv)
{
  if (argc != max_args)
  {
    fprintf(stderr, "usage: ./process [html_file]\n");
    return exit_failure;
  }

  char *html_contents = get_contents(argv[html_file_pos]);
  if (html_contents == null)
  {
    fprintf(stderr, "something went wrong loading in the content\n");
  }

  char *removed_header = strstr(html_contents, "<");
  char *body_contents = parse_body(removed_header);

  // printf("%s", body_contents);
  char response_body[100000] = {0};

  llmproxy_request(model_id, "summarize the following content", body_contents, response_body);
  printf("%s\n", response_body);

  free(html_contents);
  free(body_contents);
  return 0;
}
