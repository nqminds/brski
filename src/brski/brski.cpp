#include <stdlib.h>
#include <libgen.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "masa/masa_server.h"
#include "pledge/pledge_request.h"
#include "registrar/registrar_server.h"

extern "C" {
#include "../utils/log.h"
#include "../utils/os.h"
#include "config.h"
#include "pledge/pledge_utils.h"
}

#include "version.h"

#define OPT_STRING ":c:o:dvh"
#define USAGE_STRING                                                           \
  "\t%s [-c filename] [-o filename] [-d] [-h] [-v] <command>\n"

enum COMMAND_ID {
  COMMAND_UNKNOWN = 0,
  COMMAND_EXPORT_PVR,
  COMMAND_PLEDGE_REQUEST,
  COMMAND_START_REGISTRAR,
  COMMAND_START_MASA,
};

struct command_config {
  const char *const label;
  enum COMMAND_ID id;
  const char *info;
};

const struct command_config command_list[] = {
    {"epvr", COMMAND_EXPORT_PVR,
     "\tepvr\t\tExport the pledge voucher request as base64 CMS file"},
    {"preq", COMMAND_PLEDGE_REQUEST,
     "\tpreq\t\tSend a pledge-voucher request to the registrar"},
    {"registrar", COMMAND_START_REGISTRAR, "\tregistrar\tStarts the registrar"},
    {"masa", COMMAND_START_MASA, "\tmasa\t\tStarts the MASA"},
    {NULL, COMMAND_UNKNOWN, NULL}};

const char description_string[] = "NquiringMinds BRSKI protocol tool.\n"
                                  "\n"
                                  "Show, export and manipulate vouchers. "
                                  "Create registrar and MASA servers.\n";

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
  fprintf(stdout, "brski version %s\n", BRSKI_VERSION);
}

void show_help(char *name) {
  show_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, USAGE_STRING "\n", basename(name));
  fprintf(stdout, "%s", description_string);
  fprintf(stdout, "\nCommands:\n");
  int idx = 0;
  while (command_list[idx].label != NULL) {
    fprintf(stdout, "%s\n", command_list[idx].info);
    idx++;
  }
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "\t-c filename\t Path to the config file\n");
  fprintf(stdout, "\t-o filename\t Path to the exported file\n");
  fprintf(
      stdout,
      "\t-d\t\t Verbosity level (use multiple -dd... to increase verbosity)\n");
  fprintf(stdout, "\t-h\t\t Show help\n");
  fprintf(stdout, "\t-v\t\t Show app version\n\n");
  fprintf(stdout, "Copyright Nquiringminds Ltd\n\n");
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
}

enum COMMAND_ID get_command_id(char *command_label) {
  int idx = 0;

  if (command_label == NULL) {
    return COMMAND_UNKNOWN;
  }

  while (command_list[idx].label != NULL) {
    if (strcmp(command_list[idx].label, command_label) == 0) {
      return command_list[idx].id;
    }
    idx++;
  }

  return COMMAND_UNKNOWN;
}

void process_options(int argc, char *argv[], uint8_t *verbosity,
                     char **config_filename, char **out_filename,
                     enum COMMAND_ID *command_id) {
  int opt;

  while ((opt = getopt(argc, argv, OPT_STRING)) != -1) {
    switch (opt) {
      case 'h':
        show_help(argv[0]);
        exit(EXIT_SUCCESS);
      case 'v':
        show_version();
        exit(EXIT_SUCCESS);
      case 'c':
        *config_filename = strdup(optarg);
        break;
      case 'o':
        *out_filename = strdup(optarg);
        break;
      case 'd':
        (*verbosity)++;
        break;
      case ':':
        log_cmdline_error("Missing argument for -%c\n", optopt);
        exit(EXIT_FAILURE);
      case '?':
        log_cmdline_error("Unrecognized option -%c\n", optopt);
        exit(EXIT_FAILURE);
      default:
        show_help(argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  char *command_label = argv[optind];

  if (optind <= 1 && command_label == NULL) {
    show_help(argv[0]);
    exit(EXIT_SUCCESS);
  }

  if ((*command_id = get_command_id(command_label)) == COMMAND_UNKNOWN) {
    log_cmdline_error("Unrecognized command \"%s\"\n", command_label);
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  struct brski_config config;

  // Init the app config struct
  memset(&config, 0, sizeof(struct brski_config));

  uint8_t verbosity = 0;
  uint8_t level = 0;
  char *config_filename = NULL, *out_filename = NULL;
  enum COMMAND_ID command_id = COMMAND_UNKNOWN;

  process_options(argc, argv, &verbosity, &config_filename, &out_filename,
                  &command_id);

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
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

  struct RegistrarContext *rcontext = NULL;
  struct MasaContext *mcontext = NULL;
  std::string response;
  switch (command_id) {
    case COMMAND_EXPORT_PVR:
      fprintf(stdout, "Exporting pledge voucher request to %s", out_filename);
      if (voucher_pledge_request_to_smimefile(
              &config.pconf, config.rconf.tls_cert_path, out_filename) < 0) {
        fprintf(stderr, "voucher_pledge_request_to_smimefile fail");
        return EXIT_FAILURE;
      }
      break;
    case COMMAND_PLEDGE_REQUEST:
      fprintf(stdout, "Pledge voucher request to %s:%d\n",
              config.rconf.bind_address, config.rconf.port);
      if (post_voucher_pledge_request(&config.pconf, &config.rconf,
                                      &config.mconf, response) < 0) {
        fprintf(stderr, "post_voucher_pledge_request fail");
        return EXIT_FAILURE;
      }
      fprintf(stdout, "%s\n", response.c_str());
      break;
    case COMMAND_START_REGISTRAR:
      if (registrar_start(&config.rconf, &config.mconf, &config.pconf,
                          &rcontext) < 0) {
        fprintf(stderr, "https_start fail");
        return EXIT_FAILURE;
      }

      registrar_stop(rcontext);
      break;
    case COMMAND_START_MASA:
      if (masa_start(&config.rconf, &config.mconf, &config.pconf, &mcontext) <
          0) {
        fprintf(stderr, "https_start fail");
        return EXIT_FAILURE;
      }

      masa_stop(mcontext);
      break;
  }

  if (config_filename != NULL) {
    sys_free(config_filename);
  }

  free_config_content(&config);

  pthread_mutex_destroy(&log_lock);

  return EXIT_SUCCESS;
}
