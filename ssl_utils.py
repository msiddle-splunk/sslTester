import logging
import os
import sys
from datetime import datetime
import yaml
from dotenv import load_dotenv

load_dotenv()

day = datetime.today().strftime("%Y-%m-%d")

# Default logging configuration
logging.basicConfig(
    filename=f"/tmp/sslTester_{day}.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)


def get_config() -> dict[list[tuple[str, dict]]]:
    """Load config"""
    try:
        with open("config.yaml", "r", encoding="utf-8") as ymlconfig:
            cfg = yaml.safe_load(ymlconfig)
            return cfg.items()
    except FileNotFoundError:
        logging.error("Config file not found...exiting")
        sys.exit()


def get_splunk_hec_config() -> dict:
    url = os.getenv("HEC_ENDPOINT")
    token = os.getenv("HEC_TOKEN")
    if not url or not token:
        logging.error(
            "HEC URL or Token not found in .env or environment variables...exiting"
        )
        sys.exit()
    return {"url": url, "token": token}


def set_logging(logger) -> None:
    logpath = logger[1]["path"]
    logfile = f"{logpath}/sslTester_errors.log"
    logging.basicConfig(
        filename=logfile,
        filemode="w",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
