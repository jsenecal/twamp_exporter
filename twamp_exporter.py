#!/usr/bin/env python3
from prometheus_client import CollectorRegistry, Gauge, Info, Counter, Enum, start_http_server
import configparser
import click
import click_log
import functools
import queue
import time
import datetime
import threading
import schedule
import platform
import subprocess
import logging
logger = logging.getLogger(__name__)
click_log.basic_config(logger)

running_threads = Gauge('twping_running_total',
                        'Current number of concurrently running tests')

jobqueue = queue.Queue()

SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
NTP_EPOCH = datetime.date(1900, 1, 1)
NTP_DELTA = (SYSTEM_EPOCH - NTP_EPOCH).days * 24 * 3600

SYNC_STATES = [
    "Unknown",
    "Synced"
]


def ntp_to_system_time(ts):
    """convert a NTP time to system time"""
    return int(ts) - NTP_DELTA


def sync_to_state(status):
    return SYNC_STATES[int(status)]


DEFAULT_SLEEP_SECONDS = 60

CONFIG_DEFAULTS = {
    'count': "",
    'DSCP': "",
    'interval': "",
    'timeout': "",
    'portRange': "",
    'padding': "",
    'delay': "",
    'srcAddr': "",
    'dstAddr': "",
    'authMode': "",
    'username': "",
    'passphraseFile': "",
}

TWPING_PARAMS_MAP = {
    'count': '-c',
    'DSCP': '-D',
    'interval': '-i',
    'timeout': '-L',
    'portRange': '-P',
    'padding': '-s',
    'delay': '-z',
    'srcAddr': '-S',
    'authMode': "-A",
    'username': "-u",
    'passphraseFile': "-k",
}

TWPING_OUTPUT_TYPES_MAP = {
    'SID': str,
    'FROM_HOST': str,
    'FROM_ADDR': str,
    'FROM_PORT': int,
    'TO_HOST': str,
    'TO_ADDR': str,
    'TO_PORT': int,
    'START_TIME': ntp_to_system_time,
    'END_TIME': ntp_to_system_time,
    'DSCP': str,
    'LOSS_TIMEOUT': int,
    'PACKET_PADDING': int,
    'SESSION_PACKET_COUNT': int,
    'SENT': int,
    'SYNC': sync_to_state,
    'MAXERR': float,
    'MAXERR_FWD': float,
    'MAXERR_BCK': float,
    'DUPS_FWD': int,
    'DUPS_BCK': int,
    'LOST': int,
    'MIN': float,
    'MIN_FWD': float,
    'MIN_BCK': float,
    'MIN_PROC': float,
    'MEDIAN': float,
    'MEDIAN_FWD': float,
    'MEDIAN_BCK': float,
    'MAX': float,
    'MAX_FWD': float,
    'MAX_BCK': float,
    'MAX_PROC': float,
    'PDV': float,
    'PDV_FWD': float,
    'PDV_BCK': float,
    'MINTTL_FWD': int,
    'MAXTTL_FWD': int,
    'MINTTL_BCK': int,
    'MAXTTL_BCK': int
}


def catch_exceptions(cancel_on_failure=False):
    def catch_exceptions_decorator(job_func):
        @functools.wraps(job_func)
        def wrapper(*args, **kwargs):
            try:
                return job_func(*args, **kwargs)
            except:
                import traceback
                logger.error(traceback.format_exc())
                if cancel_on_failure:
                    return schedule.CancelJob
        return wrapper
    return catch_exceptions_decorator


def build_twping_args(conf):
    args = []
    for param in TWPING_PARAMS_MAP.keys():
        if conf[param] is not "":
            args.append(TWPING_PARAMS_MAP[param])
            args.append(conf[param])

    if conf.getboolean('forceV4'):
        args.append("-4")
    if conf.getboolean('forceV6'):
        args.append("-6")

    # We need "machine readable" output
    args.append("-M")

    if conf['dstAddr'] == "":
        conf['dstAddr'] = conf.name

    args.append(conf['dstAddr'])

    return args


LABELS = [
    'job',
    'instance',
    'to_host',
    'to_addr',
    # 'to_port',
    'from_host',
    'from_addr',
    # 'from_port',
    # 'sid',
    'dscp'
]

PROMETHEUS_METRICS_MAP = {
    # 'DSCP': Info('twping_dscp_value', 'RFC 2474 style DSCP value for TOS byte'),

    'DUPS_BCK': Gauge('twping_sender_duplicates_total', 'Send duplicates', LABELS),
    'DUPS_FWD': Gauge('twping_fwd_duplicates_total', 'Reflect duplicates', LABELS),

    'START_TIME': Gauge('twping_start_unixtime', 'Time at which the twping job started', LABELS),
    'END_TIME': Gauge('twping_stop_unixtime', 'Time at which the twping job stopped', LABELS),
    # 'LOSS_TIMEOUT': 8592120730,

    'SENT': Gauge('twping_sent_packets_total', 'Sent packets', LABELS),
    'LOST': Gauge('twping_lost_packets_total', 'Lost packets', LABELS),

    'MIN': Gauge('twping_rtt_min_seconds', 'Round-Trip time min', LABELS),
    'MEDIAN': Gauge('twping_rtt_med_seconds', 'Round-Trip time median', LABELS),
    'MAX': Gauge('twping_rtt_max_seconds', 'Round-Trip time max', LABELS),
    'MAXERR': Gauge('twping_rtt_err_seconds', 'Round-Trip time err', LABELS),

    'MIN_BCK': Gauge('twping_sender_min_seconds', 'Sender time min', LABELS),
    'MEDIAN_BCK': Gauge('twping_sender_med_seconds', 'Sender time median', LABELS),
    'MAX_BCK': Gauge('twping_sender_max_seconds', 'Sender time max', LABELS),
    'MAXERR_BCK': Gauge('twping_sender_err_seconds', 'Sender time err', LABELS),

    'MIN_FWD': Gauge('twping_fwd_min_seconds', 'Reflector time min', LABELS),
    'MEDIAN_FWD': Gauge('twping_fwd_med_seconds', 'Reflector time median', LABELS),
    'MAX_FWD': Gauge('twping_fwd_max_seconds', 'Reflector time max', LABELS),
    'MAXERR_FWD': Gauge('twping_fwd_err_seconds', 'Reflector time err', LABELS),

    'MIN_PROC': Gauge('twping_fwd_processing_min_seconds', 'Reflector processing time min', LABELS),
    'MAX_PROC': Gauge('twping_fwd_processing_max_seconds', 'Reflector processing time median', LABELS),

    'MINTTL_BCK': Gauge('twping_sender_ttl_min_value', 'Sender ttl min', LABELS),
    'MAXTTL_BCK': Gauge('twping_sender_ttl_max_value', 'Sender ttl max', LABELS),

    'MINTTL_FWD': Gauge('twping_fwd_ttl_min_value', 'Reflector ttl min', LABELS),
    'MAXTTL_FWD': Gauge('twping_fwd_ttl_max_value', 'Reflector ttl max', LABELS),

    'PACKET_PADDING': Gauge('twping_padding_bytes', 'Padding bytes', LABELS),
    'PDV': Gauge('twping_jitter_seconds', 'Two-way jitter (P95-P50)', LABELS),
    'PDV_BCK': Gauge('twping_fwd_jitter_seconds', 'Reflector jitter (P95-P50)', LABELS),
    'PDV_FWD': Gauge('twping_sender_jitter_seconds', 'Sender jitter (P95-P50)', LABELS),
    'SESSION_PACKET_COUNT': Gauge('twping_session_packets_total', 'Session packets', LABELS),
    'SYNC': Enum('twping_ntp_state', 'Synced with NTP', LABELS, states=SYNC_STATES),
}


@catch_exceptions(cancel_on_failure=True)
def twping_job(destination_section):
    logger.debug("running on thread %s" % threading.current_thread())

    args = build_twping_args(destination_section)
    logger.info("Starting twping with args: " + str(args))
    twping = subprocess.run(
        ['twping', *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    if twping.stderr:
        logger.error(twping.stderr)
    if twping.returncode is 0:
        output = twping.stdout
        stats = {
            stat.split('\t')[0]: TWPING_OUTPUT_TYPES_MAP[stat.split(
                '\t')[0]](stat.split('\t')[1])
            for stat in output.split('\n')[1:] if stat.split('\t')[0] in TWPING_OUTPUT_TYPES_MAP.keys()
        }
        logger.debug(stats)
        labels = {label: stats[label.upper()]
                  for label in LABELS if label.upper() in stats.keys()}
        labels['job'] = destination_section.name
        labels['instance'] = platform.node()
        logger.debug("prometheus labels:" + str(labels))
        for stat in PROMETHEUS_METRICS_MAP.keys():
            metric = PROMETHEUS_METRICS_MAP[stat]
            if isinstance(metric, Gauge):
                metric.labels(**labels).set(stats[stat])
            if isinstance(metric, Enum):
                metric.labels(**labels).state(stats[stat])
            if isinstance(metric, Info):
                metric.labels(**labels).info(stats[stat])
        logger.info("twping with args: {} completed successfully".format(str(args)))

    logger.debug("done running on thread %s" % threading.current_thread())


def twping_worker():
    while True:
        dest = jobqueue.get()
        if dest is None:
            break
        with running_threads.track_inprogress():
            twping_job(dest)
        jobqueue.task_done()


@click.command()
@click.option('-c', '--config', type=click.Path(exists=True, readable=True), default="twamp.ini", help="Configuration file location, defaults to 'twamp.ini' in the current directory")
@click.option('-t', '--thread-count', default=1, help="Maximum number of parallel operations", envvar='THREAD_COUNT')
@click.option('-s', '--sleep', default=DEFAULT_SLEEP_SECONDS, help="How long do we wait between each twping tests? (Overriden by config-file)", envvar="SLEEP_SECONDS")
@click_log.simple_verbosity_option(logger, envvar="VERBOSITY")
def runner(config, thread_count, sleep):
    conf = configparser.ConfigParser(CONFIG_DEFAULTS)
    conf['DEFAULT']['sleepSeconds'] = str(sleep)
    conf.read(config)

    start_http_server(9090)

    for section in conf.sections():
        logger.debug("queueing config section {} to run each {} seconds".format(section, conf[section].getint('sleepSeconds')))
        schedule.every(
            conf[section].getint('sleepSeconds')
        ).seconds.do(jobqueue.put, conf[section])

    threads = []
    for i in range(thread_count):
        thread = threading.Thread(target=twping_worker)
        thread.start()
        threads.append(thread)
    try:
        while 1:
            schedule.run_pending()
            time.sleep(1)
            # block until all tasks are done
            jobqueue.join()
    except KeyboardInterrupt:
        # stop workers
        for i in range(thread_count):
            jobqueue.put(None)
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    runner()  # pylint: disable=no-value-for-parameter
