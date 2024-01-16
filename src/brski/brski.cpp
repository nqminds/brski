#include <stdexcept>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

#include "masa/masa_server.hpp"
#include "pledge/pledge_request.hpp"
#include "registrar/registrar_server.hpp"

extern "C" {
#include "../utils/log.h"
#include "../utils/os.h"
#include "../voucher/serialize.h"
#include "config.h"
#include "pledge/pledge_utils.h"

// declare here, since we pass a pointer to this to C code
void log_lock_fun(bool lock);
}

#include "version.h"

const std::string OPT_STRING = ":c:o:p:a:dvh";
const std::string USAGE_STRING = "\t%s [-c filename] [-o filename] [-p port] "
                                 "[-a address] [-d] [-h] [-v] <command>\n";

enum class CommandId {
  COMMAND_EXPORT_PVR = 1,
  COMMAND_PLEDGE_REQUEST,
  COMMAND_SIGN_CERT,
  COMMAND_START_REGISTRAR,
  COMMAND_START_MASA,
};

struct command_config {
  const std::string label;
  CommandId id;
  const std::string info;
};

const std::array<struct command_config, 5> command_list = {{
    {"epvr", CommandId::COMMAND_EXPORT_PVR,
     "\tepvr\t\tExport the pledge voucher request as base64 CMS file"},
    {"preq", CommandId::COMMAND_PLEDGE_REQUEST,
     "\tpreq\t\tSend a pledge-voucher request to the registrar and\n"
     "\t\t\t return the pinned-domain-cert."},
    {"sign", CommandId::COMMAND_SIGN_CERT, "\tsign\t\tSign a certificate\n"},
    {"registrar", CommandId::COMMAND_START_REGISTRAR,
     "\tregistrar\tStarts the registrar"},
    {"masa", CommandId::COMMAND_START_MASA, "\tmasa\t\tStarts the MASA"},
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

static void show_version(void) {
  std::fprintf(stdout, "brski version %s\n", BRSKI_VERSION);
}

static void show_help(const char *name) {
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
  std::fprintf(stdout, "\t-o filename\t The output file\n");
  std::fprintf(stdout, "\t-p port\t The registrar port number\n");
  std::fprintf(stdout, "\t-a address\t The registrar peer address\n");
  std::fprintf(stdout, "\t-d\t\t Make verbose\n");
  std::fprintf(stdout, "\t-h\t\t Show help\n");
  std::fprintf(stdout, "\t-v\t\t Show app version\n\n");
  std::fprintf(stdout, "Copyright Nquiringminds Ltd\n\n");
}

/* Diagnose an error in command-line arguments and
   terminate the process */
[[gnu::format(printf, 1, 2)]] static void log_cmdline_error(const char *format,
                                                            ...) {
  std::va_list argList;

  std::fflush(stdout); /* Flush any pending stdout */

  std::fprintf(stdout, "Command-line usage error: ");
  va_start(argList, format);
  std::vfprintf(stdout, format, argList);
  va_end(argList);

  std::fflush(stderr); /* In case stderr is not line-buffered */
}

static CommandId get_command_id(const std::string &command_label) {
  for (const auto &command_config : command_list) {
    if (command_config.label == command_label) {
      return command_config.id;
    }
  }

  throw std::invalid_argument("Unrecognized command: \"" + command_label + '"');
}

static void process_options(int argc, char *const argv[], int &verbose,
                            std::string &config_filename,
                            std::string &out_filename, unsigned int *port,
                            std::string &address, CommandId &command_id) {
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
      case 'p':
        *port = strtol(optarg, NULL, 10);
        break;
      case 'a':
        address.assign(optarg);
        break;
      case 'd':
        verbose = 1;
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

  try {
    command_id = get_command_id(command_label);
  } catch (const std::invalid_argument &ex) {
    log_cmdline_error("%s\n", ex.what());
    show_help(argv[0]);
    std::exit(EXIT_FAILURE);
  }
}

struct BrskiConfig : public brski_config {
  virtual ~BrskiConfig() { free_config_content(this); }
};

void print_cert(const char *cert, int prefix) {
  if (prefix)
    std::fprintf(stdout, "-----BEGIN CERTIFICATE-----\n");

  std::fprintf(stdout, "%s\n", cert);

  if (prefix)
    std::fprintf(stdout, "-----END CERTIFICATE-----\n");
}

void print_key(const char *key, int prefix) {
  if (prefix)
    std::fprintf(stdout, "-----BEGIN PRIVATE KEY-----\n");

  std::fprintf(stdout, "%s\n", key);

  if (prefix)
    std::fprintf(stdout, "-----END PRIVATE KEY-----\n");
}

int main(int argc, char *argv[]) {
  int verbose = 0;
  unsigned int port = 0;
  std::string config_filename, in_filename, out_filename;
  std::string address;
  CommandId command_id;
  char outf[255];

  process_options(argc, argv, verbose, config_filename, out_filename, &port,
                  address, command_id);

  log_set_lock(log_lock_fun);

  /* Set the log level */
  if (!verbose)
    log_set_quiet(true);
  else
    log_set_level(LOGC_TRACE);

  BrskiConfig config;
  if (load_brski_config(config_filename.c_str(), &config) < 0) {
    log_error("load_config fail");
    return EXIT_FAILURE;
  }

  if (command_id == CommandId::COMMAND_PLEDGE_REQUEST ||
      command_id == CommandId::COMMAND_SIGN_CERT ||
      command_id == CommandId::COMMAND_START_REGISTRAR) {
    if (port)
      config.rconf.port = port;

    if (!address.empty()) {
      if (config.rconf.bind_address != NULL)
        sys_free(config.rconf.bind_address);

      if ((config.rconf.bind_address = strdup(address.c_str())) == NULL) {
        log_errno("strdup fail");
        return EXIT_FAILURE;
      }
    }
  }

  struct RegistrarContext *rcontext = NULL;
  struct MasaContext *mcontext = NULL;
  struct BinaryArray *tls_cert = NULL;
  switch (command_id) {
    case CommandId::COMMAND_EXPORT_PVR:
      log_info("Exporting pledge voucher request to %s", out_filename.c_str());

      tls_cert = file_to_x509buf(config.rconf.tls_cert_path);
      if (tls_cert == NULL) {
        log_error("file_to_x509buf fail");
        return EXIT_FAILURE;
      }

      if (out_filename.empty()) {
        char *base64 =
            voucher_pledge_request_to_base64(&config.pconf, tls_cert);
        if (base64 == NULL) {
          log_error("voucher_pledge_request_to_base64 fail");
          free_binary_array(tls_cert);
          return EXIT_FAILURE;
        }
        std::fprintf(stdout, "%s\n", base64);
        sys_free(base64);
        free_binary_array(tls_cert);
      } else {
        snprintf(outf, 255, "%s.smime", out_filename.c_str());

        if (voucher_pledge_request_to_smimefile(&config.pconf, tls_cert, outf) <
            0) {
          log_error("voucher_pledge_request_to_smimefile fail");
          return EXIT_FAILURE;
        }
        free_binary_array(tls_cert);
      }
      break;
    case CommandId::COMMAND_PLEDGE_REQUEST: {
      struct BinaryArray pinned_domain_cert = {};

      log_info("Pledge voucher request to %s:%d", config.rconf.bind_address,
               config.rconf.port);
      if (post_voucher_pledge_request(&config.pconf, &config.rconf,
                                      &config.mconf, &pinned_domain_cert) < 0) {
        log_error("post_voucher_pledge_request fail");
        return EXIT_FAILURE;
      }

      if (out_filename.empty()) {
        char *cert_str = NULL;

        if (serialize_array2base64str(pinned_domain_cert.array,
                                      pinned_domain_cert.length,
                                      (uint8_t **)&cert_str) < 0) {
          log_error("serialize_array2base64str fail");
          return EXIT_FAILURE;
        }
        print_cert(cert_str, 0);
        sys_free(cert_str);
      } else {
        snprintf(outf, 255, "%s.crt", out_filename.c_str());
        if (certbuf_to_file(&pinned_domain_cert, outf) < 0) {
          log_error("certbuf_to_file fail");
          return EXIT_FAILURE;
        }
      }
      free_binary_array_content(&pinned_domain_cert);
      break;
    }

    case CommandId::COMMAND_SIGN_CERT: {
      log_info("Sign cert %s:%d", config.rconf.bind_address, config.rconf.port);
      struct BinaryArray out_cert = {};
      struct BinaryArray out_key = {};

      if (post_sign_cert(&config.pconf, &config.rconf, &config.mconf, &out_cert,
                         &out_key) < 0) {
        log_error("post_voucher_pledge_request fail");
        return EXIT_FAILURE;
      }

      if (out_filename.empty()) {
        char *pki_str = NULL;

        if (serialize_array2base64str(out_cert.array, out_cert.length,
                                      (uint8_t **)&pki_str) < 0) {
          log_error("serialize_array2base64str fail");
          return EXIT_FAILURE;
        }
        print_cert(pki_str, 0);
        sys_free(pki_str);

        if (serialize_array2base64str(out_key.array, out_key.length,
                                      (uint8_t **)&pki_str) < 0) {
          log_error("serialize_array2base64str fail");
          return EXIT_FAILURE;
        }
        print_cert(pki_str, 0);
        sys_free(pki_str);
      } else {
        snprintf(outf, 255, "%s.crt", out_filename.c_str());
        if (certbuf_to_file(&out_cert, outf) < 0) {
          log_error("certbuf_to_file fail");
          return EXIT_FAILURE;
        }
        snprintf(outf, 255, "%s.key", out_filename.c_str());
        if (keybuf_to_file(&out_key, outf) < 0) {
          log_error("certbuf_to_file fail");
          return EXIT_FAILURE;
        }
      }

      free_binary_array_content(&out_cert);
      free_binary_array_content(&out_key);
      break;
    }

    case CommandId::COMMAND_START_REGISTRAR:
      if (registrar_start(&config.rconf, &config.mconf, &config.pconf,
                          &rcontext) < 0) {
        log_error("https_start fail");
        return EXIT_FAILURE;
      }

      registrar_stop(rcontext);
      break;
    case CommandId::COMMAND_START_MASA:
      if (masa_start(&config.rconf, &config.mconf, &config.pconf, &mcontext) <
          0) {
        log_error("https_start fail");
        return EXIT_FAILURE;
      }

      masa_stop(mcontext);
      break;
  }

  return EXIT_SUCCESS;
}
