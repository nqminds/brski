#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "http/https_server.h"

extern "C" {
#include "utils/os.h"
#include "utils/log.h"
}

#include "config.h"
#include "version.h"

#define OPT_STRING ":c:dvh"
#define USAGE_STRING "\t%s [-c filename] [-d] [-h] [-v]\n"
const char description_string[] =
    "NquiringMinds BRSKI Server.\n"
    "\n"
    "Creates a https EST server implementing the BRSKI protocol\n";

pthread_mutex_t log_lock;

void log_lock_fun(bool lock) {
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

void sighup_handler(int sig, void *ctx) {
  (void)sig;

  char *log_filename = (char *)ctx;

  if (log_filename != NULL) {
    log_close_file();
    log_open_file(log_filename);
  }
}

void show_version(void) {
  fprintf(stdout, "brkisi server version %s\n", BRSKI_VERSION);
}

void show_help(char *name) {
  show_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING, basename(name));
  fprintf(stdout, "%s", description_string);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-c filename\t Path to the config file name\n");
  fprintf(stdout,
          "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright Nquiringminds Ltd\n\n");
  exit(EXIT_SUCCESS);
}

/* Diagnose an error in command-line arguments and
   terminate the process */
void log_cmdline_error(const char *format, ...) {
  va_list argList;

  fflush(stdout); /* Flush any pending stdout */

  fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  vfprintf(stdout, format, argList);
  va_end(argList);

  fflush(stderr); /* In case stderr is not line-buffered */
  exit(EXIT_FAILURE);
}

void process_options(int argc, char *argv[], uint8_t *verbosity,
                         char **config_filename) {
  int opt;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
      case 'h':
        show_help(argv[0]);
        break;
      case 'v':
        show_version();
        exit(EXIT_SUCCESS);
        break;
      case 'c':
        *config_filename = strdup(optarg);
        break;
      case 'd':
        (*verbosity)++;
        break;
      case ':':
        log_cmdline_error("Missing argument for -%c\n", optopt);
        break;
      case '?':
        log_cmdline_error("Unrecognized option -%c\n", optopt);
        break;
      default:
        show_help(argv[0]);
    }
  }
}

int main(int argc, char *argv[]) {
  struct brski_config config;

  // Init the app config struct
  memset(&config, 0, sizeof(struct brski_config));

  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *config_filename = NULL;

  process_options(argc, argv, &verbosity, &config_filename);

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  if (optind <= 1) {
    show_help(argv[0]);
  }

  if (pthread_mutex_init(&log_lock, NULL) != 0) {
    fprintf(stderr, "mutex init has failed\n");
    return EXIT_FAILURE;
  }

  log_set_lock(log_lock_fun);

  /* Set the log level */
  log_set_level(level);

  if (load_brski_config(config_filename, &config) < 0) {
    fprintf(stderr, "load_config fail\n");
    return EXIT_FAILURE;
  }

  struct https_server_context *context = NULL;
  if (https_start(&context) < 0) {
    fprintf(stderr, "https_start fail");
    return EXIT_FAILURE;
  }

  https_stop(context);

  if (config_filename != NULL) {
    sys_free(config_filename);
  }

  pthread_mutex_destroy(&log_lock);

  return EXIT_SUCCESS;
}