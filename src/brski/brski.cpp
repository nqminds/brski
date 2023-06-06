#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include "masa/masa_server.h"
#include "pledge/pledge_request.h"
#include "registrar/registrar_server.h"

extern "C" {
#include "../utils/log.h"
#include "../utils/os.h"
#include "config.h"
#include "pledge/pledge_utils.h"

// declare here, since we pass a pointer to this to C code
void log_lock_fun(bool lock);
}

#include "version.h"

const std::string OPT_STRING = ":c:o:dqvh";
const std::string USAGE_STRING =
    "\t%s [-c filename] [-o filename] [-d | -q] [-h] [-v] <command>\n";

enum COMMAND_ID {
  COMMAND_UNKNOWN = 0,
  COMMAND_EXPORT_PVR,
  COMMAND_PLEDGE_REQUEST,
  COMMAND_START_REGISTRAR,
  COMMAND_START_MASA,
};

struct command_config {
  const std::string label;
  enum COMMAND_ID id;
  const std::string info;
};

const std::array<struct command_config, 4> command_list = {{
    {"epvr", COMMAND_EXPORT_PVR,
     "\tepvr\t\tExport the pledge voucher request as base64 CMS file"},
    {"preq", COMMAND_PLEDGE_REQUEST,
     "\tpreq\t\tSend a pledge-voucher request to the registrar"},
    {"registrar", COMMAND_START_REGISTRAR, "\tregistrar\tStarts the registrar"},
    {"masa", COMMAND_START_MASA, "\tmasa\t\tStarts the MASA"},
}};

const std::string description_string = "NquiringMinds BRSKI protocol tool.\n"
                                       "\n"
                                       "Show, export and manipulate vouchers. "
                                       "Create registrar and MASA servers.\n";

std::mutex log_mutex;

void log_lock_fun(bool lock) {
  if (lock) {
    log_mutex.lock();
  } else {
    log_mutex.unlock();
  }
}

void show_version(void) {
  std::fprintf(stdout, "brski version %s\n", BRSKI_VERSION);
}

void show_help(const char *name) {
  const std::string string_name(name);
  std::vector<char> basename_buffer(string_name.begin(), string_name.end());

  show_version();
  std::fprintf(stdout, "Usage:\n");
  std::fprintf(stdout, USAGE_STRING.c_str(), basename(basename_buffer.data()));
  std::fprintf(stdout, "\n");
  std::fprintf(stdout, "%s", description_string.c_str());
  std::fprintf(stdout, "\nCommands:\n");
  for (const auto &command_config : command_list) {
    std::fprintf(stdout, "%s\n", command_config.info.c_str());
  }
  std::fprintf(stdout, "\nOptions:\n");
  std::fprintf(stdout, "\t-c filename\t Path to the config file\n");
  std::fprintf(stdout, "\t-o filename\t Path to the exported file\n");
  std::fprintf(
      stdout,
      "\t-d\t\t Verbosity level (use multiple -dd... to increase verbosity)\n");
  std::fprintf(stdout,
               "\t-q\t\t Quietness (decreases verbosity) (use twice to hide "
               "warnings)\n");
  std::fprintf(stdout, "\t-h\t\t Show help\n");
  std::fprintf(stdout, "\t-v\t\t Show app version\n\n");
  std::fprintf(stdout, "Copyright Nquiringminds Ltd\n\n");
}

/* Diagnose an error in command-line arguments and
   terminate the process */
void log_cmdline_error(const char *format, ...) {
  std::va_list argList;

  std::fflush(stdout); /* Flush any pending stdout */

  std::fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  std::vfprintf(stdout, format, argList);
  va_end(argList);

  std::fflush(stderr); /* In case stderr is not line-buffered */
}

enum COMMAND_ID get_command_id(const std::string &command_label) {
  for (const auto &command_config : command_list) {
    if (command_config.label == command_label) {
      return command_config.id;
    }
  }

  return COMMAND_UNKNOWN;
}

void process_options(int argc, char *const argv[], int &quietness,
                     std::string &config_filename, std::string &out_filename,
                     enum COMMAND_ID &command_id) {
  int opt;

  while ((opt = getopt(argc, argv, OPT_STRING.c_str())) != -1) {
    switch (opt) {
      case 'h':
        show_help(argv[0]);
        std::exit(EXIT_SUCCESS);
      case 'v':
        show_version();
        std::exit(EXIT_SUCCESS);
      case 'c':
        config_filename.assign(optarg);
        break;
      case 'o':
        out_filename.assign(optarg);
        break;
      case 'd':
        quietness--;
        break;
      case 'q':
        quietness++;
        break;
      case ':':
        log_cmdline_error("Missing argument for -%c\n", optopt);
        std::exit(EXIT_FAILURE);
      case '?':
        log_cmdline_error("Unrecognized option -%c\n", optopt);
        std::exit(EXIT_FAILURE);
      default:
        show_help(argv[0]);
        std::exit(EXIT_FAILURE);
    }
  }

  const char *command_label = argv[optind];

  if (optind <= 1 && command_label == NULL) {
    show_help(argv[0]);
    std::exit(EXIT_SUCCESS);
  }

  if (command_label == nullptr) {
    log_cmdline_error("Missing required parameter <command>\n");
    show_help(argv[0]);
    exit(EXIT_FAILURE);
  }

  if ((command_id = get_command_id(command_label)) == COMMAND_UNKNOWN) {
    log_cmdline_error("Unrecognized command \"%s\"\n", command_label);
    std::exit(EXIT_FAILURE);
  }
}

struct BrskiConfig : public brski_config {
  virtual ~BrskiConfig() { free_config_content(this); }
};

int main(int argc, char *argv[]) {
  int quietness = LOGC_INFO;
  uint8_t log_level = 0;
  std::string config_filename, out_filename;
  enum COMMAND_ID command_id = COMMAND_UNKNOWN;

  process_options(argc, argv, quietness, config_filename, out_filename,
                  command_id);

  // Clamp quietness to valid log levels enum value
  // equivalent to C++17 std::clamp(quietness, 0, MAX_LOG_LEVELS - 1)
  if (quietness >= MAX_LOG_LEVELS) {
    log_level = MAX_LOG_LEVELS - 1;
  } else if (quietness < 0) {
    log_level = 0;
  } else {
    log_level = quietness;
  }

  log_set_lock(log_lock_fun);

  /* Set the log level */
  log_set_level(log_level);

  BrskiConfig config;
  if (load_brski_config(config_filename.c_str(), &config) < 0) {
    std::fprintf(stderr, "load_config fail\n");
    return EXIT_FAILURE;
  }

  struct RegistrarContext *rcontext = NULL;
  struct MasaContext *mcontext = NULL;
  std::string response;
  switch (command_id) {
    case COMMAND_EXPORT_PVR:
      std::fprintf(stdout, "Exporting pledge voucher request to %s",
                   out_filename.c_str());
      if (voucher_pledge_request_to_smimefile(&config.pconf,
                                              config.rconf.tls_cert_path,
                                              out_filename.c_str()) < 0) {
        std::fprintf(stderr, "voucher_pledge_request_to_smimefile fail");
        return EXIT_FAILURE;
      }
      break;
    case COMMAND_PLEDGE_REQUEST:
      std::fprintf(stdout, "Pledge voucher request to %s:%d\n",
                   config.rconf.bind_address, config.rconf.port);
      if (post_voucher_pledge_request(&config.pconf, &config.rconf,
                                      &config.mconf, response) < 0) {
        std::fprintf(stderr, "post_voucher_pledge_request fail");
        return EXIT_FAILURE;
      }
      std::fprintf(stdout, "%s\n", response.c_str());
      break;
    case COMMAND_START_REGISTRAR:
      if (registrar_start(&config.rconf, &config.mconf, &config.pconf,
                          &rcontext) < 0) {
        std::fprintf(stderr, "https_start fail");
        return EXIT_FAILURE;
      }

      registrar_stop(rcontext);
      break;
    case COMMAND_START_MASA:
      if (masa_start(&config.rconf, &config.mconf, &config.pconf, &mcontext) <
          0) {
        std::fprintf(stderr, "https_start fail");
        return EXIT_FAILURE;
      }

      masa_stop(mcontext);
      break;
  }

  return EXIT_SUCCESS;
}
