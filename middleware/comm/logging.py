import logging
import logging.config

def configure_logging(config_path):
    try:
        logging.config.fileConfig(config_path)
        _getlogger().info("Loaded logging configuration from '%s'", config_path)
    except Exception as e:
        _load_default_configuration()
        _getlogger().info("Loaded default logging configuration ('%s' invalid)", config_path)
        _getlogger().debug("While loading from '%s': %s", config_path, str(e))

def _load_default_configuration():
    logging.config.dictConfig({
        "version": 1,
        "formatters": {
            "user": {
                "format": "[%(levelname)s:%(name)s] %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "user",
                "stream": "ext://sys.stdout"
            }
        },
        "root": {
            "level": "NOTSET",
            "handlers": ["console"]
        },
    })

def _getlogger():
    return logging.getLogger("logging")
