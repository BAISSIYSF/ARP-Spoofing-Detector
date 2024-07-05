import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

CONFIG_PATH = 'config/config_mails.json'

def load_emails():
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    return config.get('alert_emails', [])

def save_emails(emails):
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
    config['alert_emails'] = emails
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def send_email_alert(receivers, subject, body):
    print("mail sending 1")
    sender_email = 'your_email'
    sender_password = 'your_key_passwd' 

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = ', '.join(receivers)
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    print("mail sending 2")
    server.starttls()
    server.login(sender_email, sender_password)
    print("mail sending 3")
    text = message.as_string()
    server.sendmail(sender_email, receivers, text)
    print("mail sending 4")
    server.quit()
    logging.info('Email alert sent.')
