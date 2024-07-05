import logging

def setup_logger():
    logging.basicConfig(
        filename='logs/arp_spoofing_detector.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("Logger is set up")